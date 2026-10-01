"""Tests for case builder.

Tests:
- Grouping by shared pulse
- Grouping by shared CVE
- Grouping by shared resolved IP
- Singleton handling
- Cap enforcement (max 25 per case)
"""

from __future__ import annotations

import pytest

from threatweave.cases.builder import MAX_CASE_SIZE, build_cases
from threatweave.models.indicators import (
    EnrichedIndicator,
    RawIndicator,
    generate_ioc_id,
)


def _make_enriched(
    ioc_type: str,
    value: str,
    source: str = "test",
    context: str = "",
    enrichment: dict | None = None,
) -> EnrichedIndicator:
    """Create a test enriched indicator."""
    ioc_id = generate_ioc_id(ioc_type, value, source)
    raw = RawIndicator(
        ioc_id=ioc_id,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        value=value,
        source=source,
        source_context=context,
    )
    return EnrichedIndicator(
        indicator=raw,
        enrichment=enrichment or {},
        enrichment_status="ok",
    )


class TestSingletonHandling:
    """Tests for single-indicator case creation."""

    def test_single_indicator_becomes_singleton(self) -> None:
        """A single indicator should create one case."""
        indicators = [_make_enriched("ipv4", "1.2.3.4")]
        cases = build_cases(indicators)
        assert len(cases) == 1
        assert cases[0].grouping_reason == "Singleton indicator"
        assert len(cases[0].indicators) == 1

    def test_unrelated_indicators_become_singletons(self) -> None:
        """Unrelated indicators should each become singleton cases."""
        indicators = [
            _make_enriched("ipv4", "1.2.3.4"),
            _make_enriched("domain", "evil.com"),
            _make_enriched("sha256", "a" * 64),
        ]
        cases = build_cases(indicators)
        assert len(cases) == 3
        assert all(
            c.grouping_reason == "Singleton indicator" for c in cases
        )


class TestPulseGrouping:
    """Tests for grouping by shared OTX pulse."""

    def test_same_pulse_grouped(self) -> None:
        """Indicators from the same pulse should be grouped."""
        indicators = [
            _make_enriched(
                "ipv4",
                "1.2.3.4",
                context="Pulse: APT29 Campaign | Tags: apt",
            ),
            _make_enriched(
                "domain",
                "evil.com",
                context="Pulse: APT29 Campaign | Tags: apt",
            ),
        ]
        cases = build_cases(indicators)
        assert len(cases) == 1
        assert "Shared OTX pulse" in cases[0].grouping_reason
        assert len(cases[0].indicators) == 2

    def test_different_pulses_separate(self) -> None:
        """Indicators from different pulses should be in separate cases."""
        indicators = [
            _make_enriched(
                "ipv4", "1.2.3.4", context="Pulse: Campaign A"
            ),
            _make_enriched(
                "ipv4", "5.6.7.8", context="Pulse: Campaign A"
            ),
            _make_enriched(
                "domain", "evil.com", context="Pulse: Campaign B"
            ),
            _make_enriched(
                "domain", "bad.org", context="Pulse: Campaign B"
            ),
        ]
        cases = build_cases(indicators)
        pulse_cases = [
            c for c in cases if "Shared OTX pulse" in c.grouping_reason
        ]
        assert len(pulse_cases) == 2


class TestResolvedIpGrouping:
    """Tests for grouping by shared resolved IP."""

    def test_shared_resolved_ip_grouped(self) -> None:
        """Domains resolving to the same IP should be grouped."""
        indicators = [
            _make_enriched(
                "domain",
                "evil.com",
                enrichment={"dns": {"a_records": ["1.2.3.4"]}},
            ),
            _make_enriched(
                "domain",
                "bad.org",
                enrichment={"dns": {"a_records": ["1.2.3.4"]}},
            ),
        ]
        cases = build_cases(indicators)
        assert len(cases) == 1
        assert "Shared resolved IP" in cases[0].grouping_reason


class TestCapEnforcement:
    """Tests for case size cap."""

    def test_oversized_group_split(self) -> None:
        """Groups larger than MAX_CASE_SIZE should be split."""
        # Create 30 indicators in the same pulse
        indicators = [
            _make_enriched(
                "ipv4",
                f"10.0.0.{i}",
                context="Pulse: Big Campaign",
            )
            for i in range(30)
        ]
        cases = build_cases(indicators)

        # Should be split into 2 cases (25 + 5)
        pulse_cases = [
            c for c in cases if "Shared OTX pulse" in c.grouping_reason
        ]
        assert len(pulse_cases) == 2
        sizes = sorted(len(c.indicators) for c in pulse_cases)
        assert sizes == [5, 25]


class TestEmptyInput:
    """Tests for edge cases."""

    def test_empty_input(self) -> None:
        """Empty input should return empty list."""
        assert build_cases([]) == []
