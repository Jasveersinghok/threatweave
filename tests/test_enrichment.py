"""Tests for enrichment pipeline.

Tests:
- Fake provider with success/failure
- Partial failure handling (one provider fails, other succeeds)
- Concurrency control
- Provider type filtering
"""

from __future__ import annotations

from typing import Any

import pytest

from threatweave.enrichment.base import EnrichmentProvider
from threatweave.enrichment.pipeline import enrich_indicators
from threatweave.models.indicators import RawIndicator, generate_ioc_id


# ---------------------------------------------------------------------------
# Fake providers for testing
# ---------------------------------------------------------------------------


class FakeSuccessProvider(EnrichmentProvider):
    """Always succeeds with test data."""

    @property
    def name(self) -> str:
        return "fake_success"

    @property
    def supported_types(self) -> set[str]:
        return {"ipv4", "domain"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        return {"enriched": True, "value": indicator.value}


class FakeFailProvider(EnrichmentProvider):
    """Always raises an exception."""

    @property
    def name(self) -> str:
        return "fake_fail"

    @property
    def supported_types(self) -> set[str]:
        return {"ipv4", "domain"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        msg = "Provider failed"
        raise RuntimeError(msg)


class FakeCveProvider(EnrichmentProvider):
    """Only enriches CVE indicators."""

    @property
    def name(self) -> str:
        return "fake_cve"

    @property
    def supported_types(self) -> set[str]:
        return {"cve"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        return {"cve_id": indicator.value, "found": True}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_indicator(ioc_type: str, value: str) -> RawIndicator:
    """Create a test indicator."""
    return RawIndicator(
        ioc_id=generate_ioc_id(ioc_type, value, "test"),
        ioc_type=ioc_type,  # type: ignore[arg-type]
        value=value,
        source="test",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnrichmentPipeline:
    """Tests for the enrichment pipeline."""

    @pytest.mark.asyncio()
    async def test_success_enrichment(self) -> None:
        """A successful provider should populate enrichment dict."""
        indicator = _make_indicator("ipv4", "1.2.3.4")
        result = await enrich_indicators(
            [indicator], providers=[FakeSuccessProvider()]
        )
        assert len(result) == 1
        assert result[0].enrichment_status == "ok"
        assert "fake_success" in result[0].enrichment
        assert result[0].enrichment["fake_success"]["enriched"] is True

    @pytest.mark.asyncio()
    async def test_failure_enrichment(self) -> None:
        """A failing provider should set status to 'failed'."""
        indicator = _make_indicator("ipv4", "1.2.3.4")
        result = await enrich_indicators(
            [indicator], providers=[FakeFailProvider()]
        )
        assert len(result) == 1
        assert result[0].enrichment_status == "failed"
        assert "fake_fail" in result[0].errors

    @pytest.mark.asyncio()
    async def test_partial_failure(self) -> None:
        """One success + one failure should set status to 'partial'."""
        indicator = _make_indicator("ipv4", "1.2.3.4")
        result = await enrich_indicators(
            [indicator],
            providers=[FakeSuccessProvider(), FakeFailProvider()],
        )
        assert len(result) == 1
        assert result[0].enrichment_status == "partial"
        assert "fake_success" in result[0].enrichment
        assert "fake_fail" in result[0].errors

    @pytest.mark.asyncio()
    async def test_type_filtering(self) -> None:
        """Providers should only run for supported types."""
        ip_indicator = _make_indicator("ipv4", "1.2.3.4")
        cve_indicator = _make_indicator("cve", "CVE-2024-3400")

        result = await enrich_indicators(
            [ip_indicator, cve_indicator],
            providers=[FakeSuccessProvider(), FakeCveProvider()],
        )
        assert len(result) == 2

        # IP should only have fake_success
        ip_result = result[0]
        assert "fake_success" in ip_result.enrichment
        assert "fake_cve" not in ip_result.enrichment

        # CVE should only have fake_cve
        cve_result = result[1]
        assert "fake_cve" in cve_result.enrichment
        assert "fake_success" not in cve_result.enrichment

    @pytest.mark.asyncio()
    async def test_no_applicable_providers(self) -> None:
        """Indicator with no applicable providers should get status 'ok'."""
        sha_indicator = _make_indicator("sha256", "a" * 64)
        result = await enrich_indicators(
            [sha_indicator],
            providers=[FakeCveProvider()],  # Only handles CVE
        )
        assert len(result) == 1
        assert result[0].enrichment_status == "ok"
        assert result[0].enrichment == {}

    @pytest.mark.asyncio()
    async def test_multiple_indicators(self) -> None:
        """Pipeline should handle multiple indicators."""
        indicators = [
            _make_indicator("ipv4", "1.2.3.4"),
            _make_indicator("ipv4", "5.6.7.8"),
            _make_indicator("domain", "evil.com"),
        ]
        result = await enrich_indicators(
            indicators, providers=[FakeSuccessProvider()]
        )
        assert len(result) == 3
        assert all(r.enrichment_status == "ok" for r in result)

    @pytest.mark.asyncio()
    async def test_empty_input(self) -> None:
        """Empty indicator list should return empty result."""
        result = await enrich_indicators([], providers=[FakeSuccessProvider()])
        assert result == []
