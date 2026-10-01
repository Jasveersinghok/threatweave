"""Tests for STIX 2.1 export.

Tests:
- Valid bundle generation
- Deterministic IDs
- Object types and references
- CVE vulnerability objects
- Attack pattern objects
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threatweave.export.stix_builder import (
    _deterministic_id,
    _ioc_to_stix_pattern,
    build_stix_bundle,
)
from threatweave.models.agent_state import (
    EvasionAnalysis,
    FinalReport,
    SigmaRule,
    TechniqueMapping,
    ValidationIssue,
)
from threatweave.models.case import Case
from threatweave.models.indicators import (
    EnrichedIndicator,
    RawIndicator,
    generate_ioc_id,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_case() -> Case:
    """Create a test case."""
    indicators = [
        _make_enriched("ipv4", "1.2.3.4", "C2 server"),
        _make_enriched("domain", "evil.com", "Phishing domain"),
        _make_enriched("cve", "CVE-2024-3400", "PAN-OS vuln"),
    ]
    return Case(
        case_id="test-stix-001",
        indicators=indicators,
        grouping_reason="Test case",
        created_at=datetime.now(UTC),
    )


def _make_enriched(
    ioc_type: str, value: str, context: str
) -> EnrichedIndicator:
    """Create a test enriched indicator."""
    ioc_id = generate_ioc_id(ioc_type, value, "test")
    raw = RawIndicator(
        ioc_id=ioc_id,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        value=value,
        source="test",
        source_context=context,
    )
    return EnrichedIndicator(
        indicator=raw, enrichment={}, enrichment_status="ok"
    )


def _make_report() -> FinalReport:
    """Create a test report."""
    return FinalReport(
        report_id="test-report-001",
        title="Test Report",
        executive_summary="Test summary",
        detailed_analysis="Test analysis",
        technique_table=[
            TechniqueMapping(
                technique_id="T1566.001",
                technique_name="Phishing: Spearphishing Attachment",
                tactic="initial-access",
                evidence="evil.com serves phishing pages",
                confidence="high",
            ),
        ],
        detection_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="Test Rule",
                rule_yaml="title: Test",
                rationale="Test",
                data_source="DNS",
            ),
        ],
        recommended_actions=["Block evil.com"],
        confidence_assessment="High confidence",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDeterministicIds:
    """Tests for deterministic STIX ID generation."""

    def test_same_input_same_id(self) -> None:
        """Same input should produce the same ID."""
        id1 = _deterministic_id("indicator", "ipv4:1.2.3.4")
        id2 = _deterministic_id("indicator", "ipv4:1.2.3.4")
        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Different input should produce different IDs."""
        id1 = _deterministic_id("indicator", "ipv4:1.2.3.4")
        id2 = _deterministic_id("indicator", "ipv4:5.6.7.8")
        assert id1 != id2

    def test_id_format(self) -> None:
        """IDs should follow STIX format: type--uuid."""
        stix_id = _deterministic_id("indicator", "test")
        assert stix_id.startswith("indicator--")
        parts = stix_id.split("--")
        assert len(parts) == 2


class TestStixPatterns:
    """Tests for IOC to STIX pattern conversion."""

    def test_ipv4_pattern(self) -> None:
        p = _ioc_to_stix_pattern("ipv4", "1.2.3.4")
        assert p == "[ipv4-addr:value = '1.2.3.4']"

    def test_domain_pattern(self) -> None:
        p = _ioc_to_stix_pattern("domain", "evil.com")
        assert p == "[domain-name:value = 'evil.com']"

    def test_url_pattern(self) -> None:
        p = _ioc_to_stix_pattern("url", "http://evil.com")
        assert p == "[url:value = 'http://evil.com']"

    def test_sha256_pattern(self) -> None:
        h = "a" * 64
        p = _ioc_to_stix_pattern("sha256", h)
        assert f"SHA-256' = '{h}'" in p

    def test_cve_pattern(self) -> None:
        p = _ioc_to_stix_pattern("cve", "CVE-2024-3400")
        assert "CVE-2024-3400" in p


class TestBundleGeneration:
    """Tests for full STIX bundle generation."""

    def test_bundle_has_required_fields(self) -> None:
        """Bundle should have type and objects."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        assert bundle["type"] == "bundle"
        assert "objects" in bundle
        assert len(bundle["objects"]) > 0

    def test_bundle_contains_identity(self) -> None:
        """Bundle should contain ThreatWeave identity."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        identities = [
            o for o in bundle["objects"] if o["type"] == "identity"
        ]
        assert len(identities) == 1
        assert identities[0]["name"] == "ThreatWeave"

    def test_bundle_contains_indicators(self) -> None:
        """Bundle should have indicator objects for each IOC."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        indicators = [
            o for o in bundle["objects"] if o["type"] == "indicator"
        ]
        assert len(indicators) == 3  # ipv4 + domain + cve

    def test_bundle_contains_attack_patterns(self) -> None:
        """Bundle should have attack-pattern for mapped techniques."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        attack_patterns = [
            o for o in bundle["objects"] if o["type"] == "attack-pattern"
        ]
        assert len(attack_patterns) == 1
        assert attack_patterns[0]["name"] == "Phishing: Spearphishing Attachment"

    def test_bundle_contains_vulnerability(self) -> None:
        """Bundle should have vulnerability object for CVE."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        vulns = [
            o for o in bundle["objects"] if o["type"] == "vulnerability"
        ]
        assert len(vulns) == 1
        assert vulns[0]["name"] == "CVE-2024-3400"

    def test_bundle_contains_relationships(self) -> None:
        """Bundle should have relationship objects."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        rels = [
            o for o in bundle["objects"] if o["type"] == "relationship"
        ]
        assert len(rels) >= 1
        assert all(
            r["relationship_type"] == "indicates" for r in rels
        )

    def test_bundle_contains_report(self) -> None:
        """Bundle should have a report object."""
        case = _make_case()
        report = _make_report()
        bundle = build_stix_bundle(case, report)

        reports = [
            o for o in bundle["objects"] if o["type"] == "report"
        ]
        assert len(reports) == 1
        assert reports[0]["name"] == "Test Report"

    def test_deterministic_bundle(self) -> None:
        """Same inputs should produce same object IDs."""
        case = _make_case()
        report = _make_report()

        bundle1 = build_stix_bundle(case, report)
        bundle2 = build_stix_bundle(case, report)

        ids1 = {o["id"] for o in bundle1["objects"]}
        ids2 = {o["id"] for o in bundle2["objects"]}
        assert ids1 == ids2
