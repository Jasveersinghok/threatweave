"""OTX collector — pull indicators from AlienVault OTX subscribed pulses.

Uses OTXv2 SDK for incremental fetches via modified_since. Extracts
indicators with pulse name/tags as source_context. Gracefully handles
missing OTX_API_KEY.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from threatweave.collection.normalize import normalize
from threatweave.config import get_settings
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)

# OTX indicator type → our IOC type
_OTX_TYPE_MAP: dict[str, str] = {
    "IPv4": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-SHA256": "sha256",
    "CVE": "cve",
}


def _extract_indicators_from_pulse(
    pulse: dict[str, Any],
) -> list[dict[str, str]]:
    """Extract indicators from a single OTX pulse."""
    results: list[dict[str, str]] = []
    pulse_name = pulse.get("name", "Unknown Pulse")
    tags = pulse.get("tags", [])
    context = f"Pulse: {pulse_name}"
    if tags:
        context += f" | Tags: {', '.join(tags[:10])}"

    for indicator in pulse.get("indicators", []):
        otx_type = indicator.get("type", "")
        our_type = _OTX_TYPE_MAP.get(otx_type)
        if our_type is None:
            continue

        value = indicator.get("indicator", "")
        if not value:
            continue

        results.append(
            {
                "type": our_type,
                "value": value,
                "source": "otx",
                "context": context,
            }
        )

    return results


def collect_from_otx(
    modified_since: datetime | None = None,
    limit: int = 10,
) -> list[RawIndicator]:
    """Pull subscribed pulses from OTX and extract indicators.

    Args:
        modified_since: Only fetch pulses modified after this time.
                       Defaults to 24 hours ago.
        limit: Maximum number of pulses to fetch.

    Returns:
        List of normalized RawIndicator instances.

    Raises:
        RuntimeError: If OTX_API_KEY is not configured.
    """
    settings = get_settings()
    if not settings.otx_api_key:
        logger.warning("OTX_API_KEY not configured — skipping OTX collection")
        return []

    try:
        from OTXv2 import OTXv2
    except ImportError:
        logger.warning("OTXv2 not installed — skipping OTX collection")
        return []

    if modified_since is None:
        modified_since = datetime.now(UTC).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

    logger.info(
        "Fetching OTX pulses modified since %s (limit=%d)",
        modified_since.isoformat(),
        limit,
    )

    otx = OTXv2(settings.otx_api_key)

    try:
        pulses = otx.getall(modified_since=modified_since.isoformat(), limit=limit)
    except Exception:
        logger.exception("Failed to fetch OTX pulses")
        return []

    # Extract all indicators from all pulses
    raw_indicators: list[dict[str, str]] = []
    for pulse in pulses:
        raw_indicators.extend(_extract_indicators_from_pulse(pulse))

    logger.info(
        "Extracted %d raw indicators from %d pulses",
        len(raw_indicators),
        len(pulses),
    )

    # Normalize and create RawIndicator instances
    normalized = normalize(raw_indicators, source="otx")
    indicators = [
        RawIndicator(
            ioc_id=d["ioc_id"],
            ioc_type=d["ioc_type"],  # type: ignore[arg-type]
            value=d["value"],
            source=d["source"],
            source_context=d["source_context"],
        )
        for d in normalized
    ]

    logger.info("OTX collection complete: %d indicators", len(indicators))
    return indicators
