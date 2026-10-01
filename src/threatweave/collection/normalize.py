"""Indicator normalization — refanging, validation, ID generation, dedup.

Converts defanged indicators to their canonical form, validates formats,
generates deterministic IDs, and deduplicates.
"""

from __future__ import annotations

import hashlib
import re

# ---------------------------------------------------------------------------
# Refanging patterns
# ---------------------------------------------------------------------------

_REFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"meow"), ""),
]


def refang(value: str) -> str:
    """Convert defanged indicator to its canonical form.

    Handles common defang patterns:
    - hxxp → http
    - [.] → .
    - [:] → :
    - [dot] → .
    - [at] → @
    - meow → (remove)
    """
    result = value.strip()
    for pattern, replacement in _REFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# ---------------------------------------------------------------------------
# Validation regexes
# ---------------------------------------------------------------------------

_VALIDATORS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ),
    "domain": re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.[A-Za-z0-9-]{1,63})*"
        r"\.[A-Za-z]{2,}$"
    ),
    "url": re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    ),
    "sha256": re.compile(r"^[A-Fa-f0-9]{64}$"),
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
}


def validate_indicator(ioc_type: str, value: str) -> bool:
    """Validate indicator format against type-specific regex.

    Args:
        ioc_type: One of ipv4, domain, url, sha256, cve.
        value: The refanged indicator value.

    Returns:
        True if valid, False otherwise.
    """
    pattern = _VALIDATORS.get(ioc_type)
    if pattern is None:
        return False
    return pattern.match(value) is not None


def generate_id(ioc_type: str, value: str, source: str) -> str:
    """Generate deterministic ID: SHA-256(type || value || source).

    Args:
        ioc_type: The IOC type.
        value: The normalized indicator value.
        source: The data source.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    raw = f"{ioc_type}||{value}||{source}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize(
    indicators: list[dict[str, str]],
    source: str = "manual",
) -> list[dict[str, str]]:
    """Full normalization pipeline: refang → validate → generate ID → dedup.

    Args:
        indicators: List of dicts with at least 'type' and 'value' keys.
                    Optional 'source' and 'context' keys.
        source: Default source if not specified per indicator.

    Returns:
        List of normalized, validated, deduplicated indicator dicts.
        Each dict has keys: ioc_type, value, source, source_context, ioc_id.
    """
    seen_ids: set[str] = set()
    results: list[dict[str, str]] = []

    for ind in indicators:
        ioc_type = ind.get("type", ind.get("ioc_type", "")).strip().lower()
        raw_value = ind.get("value", "").strip()
        ind_source = ind.get("source", source).strip()
        context = ind.get("context", ind.get("source_context", "")).strip()

        # Refang
        value = refang(raw_value)

        # Validate
        if not validate_indicator(ioc_type, value):
            continue

        # Generate deterministic ID
        ioc_id = generate_id(ioc_type, value, ind_source)

        # Dedup
        if ioc_id in seen_ids:
            continue
        seen_ids.add(ioc_id)

        results.append(
            {
                "ioc_type": ioc_type,
                "value": value,
                "source": ind_source,
                "source_context": context,
                "ioc_id": ioc_id,
            }
        )

    return results
