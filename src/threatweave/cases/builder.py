"""Case builder — group enriched indicators into cases.

Grouping strategy:
1. Same source pulse (OTX pulse name)
2. Shared CVE
3. Shared resolved IP (from DNS enrichment)
4. Singletons become single-indicator cases

Caps case size at 25 indicators (splits larger clusters).
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from threatweave.models.case import Case
from threatweave.models.indicators import EnrichedIndicator

logger = logging.getLogger(__name__)

MAX_CASE_SIZE = 25


def _extract_pulse_name(ei: EnrichedIndicator) -> str | None:
    """Extract OTX pulse name from source_context if present."""
    ctx = ei.indicator.source_context
    if ctx.startswith("Pulse: "):
        # "Pulse: Name | Tags: ..." → "Name"
        name = ctx.split("|")[0].replace("Pulse: ", "").strip()
        return name if name else None
    return None


def _extract_resolved_ips(ei: EnrichedIndicator) -> set[str]:
    """Extract resolved A records from DNS enrichment."""
    dns_data = ei.enrichment.get("dns", {})
    a_records = dns_data.get("a_records", [])
    return set(a_records)


def _generate_case_id() -> str:
    """Generate a unique case ID."""
    return f"case-{uuid.uuid4().hex[:12]}"


def _split_if_oversized(
    indicators: list[EnrichedIndicator],
    reason: str,
) -> list[Case]:
    """Split a group into cases of MAX_CASE_SIZE."""
    cases: list[Case] = []
    for i in range(0, len(indicators), MAX_CASE_SIZE):
        chunk = indicators[i : i + MAX_CASE_SIZE]
        suffix = f" (part {i // MAX_CASE_SIZE + 1})" if len(indicators) > MAX_CASE_SIZE else ""
        cases.append(
            Case(
                case_id=_generate_case_id(),
                indicators=chunk,
                grouping_reason=f"{reason}{suffix}",
                created_at=datetime.now(UTC),
            )
        )
    return cases


def build_cases(
    indicators: list[EnrichedIndicator],
) -> list[Case]:
    """Group enriched indicators into cases.

    Grouping priority:
    1. Same OTX pulse
    2. Shared CVE value
    3. Shared resolved IP
    4. Singletons

    Args:
        indicators: List of enriched indicators to group.

    Returns:
        List of Case objects.
    """
    if not indicators:
        return []

    logger.info("Building cases from %d indicators", len(indicators))

    assigned: set[str] = set()  # Set of assigned ioc_ids
    cases: list[Case] = []

    # --- Phase 1: Group by OTX pulse ---
    pulse_groups: dict[str, list[EnrichedIndicator]] = defaultdict(list)
    for ei in indicators:
        pulse = _extract_pulse_name(ei)
        if pulse:
            pulse_groups[pulse].append(ei)

    for pulse_name, group in pulse_groups.items():
        unassigned = [ei for ei in group if ei.indicator.ioc_id not in assigned]
        if len(unassigned) >= 2:
            cases.extend(
                _split_if_oversized(
                    unassigned,
                    f"Shared OTX pulse: {pulse_name}",
                )
            )
            assigned.update(ei.indicator.ioc_id for ei in unassigned)

    # --- Phase 2: Group by shared CVE ---
    cve_groups: dict[str, list[EnrichedIndicator]] = defaultdict(list)
    for ei in indicators:
        if ei.indicator.ioc_id in assigned:
            continue
        if ei.indicator.ioc_type == "cve":
            cve_groups[ei.indicator.value].append(ei)

    for cve_id, group in cve_groups.items():
        if len(group) >= 2:
            cases.extend(
                _split_if_oversized(group, f"Shared CVE: {cve_id}")
            )
            assigned.update(ei.indicator.ioc_id for ei in group)

    # --- Phase 3: Group by shared resolved IP ---
    ip_to_indicators: dict[str, list[EnrichedIndicator]] = defaultdict(list)
    for ei in indicators:
        if ei.indicator.ioc_id in assigned:
            continue
        for ip in _extract_resolved_ips(ei):
            ip_to_indicators[ip].append(ei)

    for ip, group in ip_to_indicators.items():
        unassigned = [ei for ei in group if ei.indicator.ioc_id not in assigned]
        if len(unassigned) >= 2:
            cases.extend(
                _split_if_oversized(
                    unassigned,
                    f"Shared resolved IP: {ip}",
                )
            )
            assigned.update(ei.indicator.ioc_id for ei in unassigned)

    # --- Phase 4: Singletons ---
    for ei in indicators:
        if ei.indicator.ioc_id not in assigned:
            cases.append(
                Case(
                    case_id=_generate_case_id(),
                    indicators=[ei],
                    grouping_reason="Singleton indicator",
                    created_at=datetime.now(UTC),
                )
            )

    logger.info(
        "Built %d cases from %d indicators",
        len(cases),
        len(indicators),
    )
    return cases
