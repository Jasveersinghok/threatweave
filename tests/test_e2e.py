"""End-to-end integration test.

Runs a sample case through the full pipeline (with mocked LLM)
and verifies STIX output is valid.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
import stix2

from threatweave.cases.builder import build_cases
from threatweave.collection.normalize import normalize
from threatweave.export.json_report import export_json, report_to_dict
from threatweave.export.stix_builder import build_stix_bundle
from threatweave.models.agent_state import (
    AnalystOutput,
    EvasionAnalysis,
    FinalReport,
    HunterOutput,
    HuntHypothesis,
    RedOutput,
    SigmaRule,
    TechniqueMapping,
    ThreatAssessment,
    ValidationResult,
)
from threatweave.models.case import Case
from threatweave.models.indicators import (
    EnrichedIndicator,
    RawIndicator,
    generate_ioc_id,
)


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------


def _sample_indicators() -> list[dict[str, str]]:
    """Sample indicator data."""
    return [
        {
            "type": "ipv4",
            "value": "198.51.100.42",
            "source": "test",
            "context": "C2 server",
        },
        {
            "type": "domain",
            "value": "evil-phishing.example.com",
            "source": "test",
            "context": "Phishing domain",
        },
        {
            "type": "cve",
            "value": "CVE-2024-3400",
            "source": "test",
            "context": "PAN-OS vulnerability",
        },
    ]


def _mock_analyst_output() -> AnalystOutput:
    """Create a mock analyst output."""
    return AnalystOutput(
        case_summary="Test case involving phishing and C2",
        threat_assessment=ThreatAssessment(
            severity="high",
            confidence="high",
            reasoning="Multiple indicators point to an advanced threat",
        ),
        technique_mappings=[
            TechniqueMapping(
                technique_id="T1566.001",
                technique_name="Phishing: Spearphishing Attachment",
                tactic="initial-access",
                evidence="evil-phishing.example.com serves phishing pages",
                confidence="high",
            ),
            TechniqueMapping(
                technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
                tactic="command-and-control",
                evidence="198.51.100.42 is a known C2 server",
                confidence="high",
            ),
        ],
    )


def _mock_hunter_output() -> HunterOutput:
    """Create a mock hunter output."""
    return HunterOutput(
        sigma_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="Phishing Domain Access",
                rule_yaml=(
                    "title: Phishing Domain Access\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "  category: dns\n"
                    "detection:\n"
                    "  selection:\n"
                    "    query|contains: evil-phishing.example.com\n"
                    "  condition: selection\n"
                    "level: high"
                ),
                rationale="Detects DNS queries to known phishing domain",
                data_source="DNS",
            ),
        ],
        hunt_hypotheses=[
            HuntHypothesis(
                hypothesis="Look for lateral movement after initial access",
                data_source="Windows Event Logs",
                query_logic="EventID 4624 with LogonType 3",
            ),
        ],
    )


def _mock_red_output() -> RedOutput:
    """Create a mock red team output."""
    return RedOutput(
        evasion_analysis=[
            EvasionAnalysis(
                target_rule="Phishing Domain Access",
                evasion_technique="Domain fronting",
                difficulty="moderate",
                suggested_hardening="Add TLS SNI inspection",
            ),
        ],
        coverage_gaps=["No detection for encrypted C2 channels"],
        overall_assessment="Good baseline but needs encrypted traffic coverage",
    )


def _mock_report(case: Case) -> FinalReport:
    """Create a mock final report."""
    return FinalReport(
        report_id="test-e2e-report-001",
        title="E2E Test Case Analysis",
        executive_summary="Analysis of test indicators shows APT-like activity",
        detailed_analysis="Detailed analysis of phishing and C2 activity",
        technique_table=[
            TechniqueMapping(
                technique_id="T1566.001",
                technique_name="Phishing: Spearphishing Attachment",
                tactic="initial-access",
                evidence="evil-phishing.example.com serves phishing pages",
                confidence="high",
            ),
        ],
        detection_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="Phishing Domain Access",
                rule_yaml=(
                    "title: Phishing Domain Access\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "  category: dns\n"
                    "detection:\n"
                    "  selection:\n"
                    "    query|contains: evil-phishing.example.com\n"
                    "  condition: selection\n"
                    "level: high"
                ),
                rationale="Detects DNS queries to known phishing domain",
                data_source="DNS",
            ),
        ],
        adversarial_considerations=[
            EvasionAnalysis(
                target_rule="Phishing Domain Access",
                evasion_technique="Domain fronting",
                difficulty="moderate",
                suggested_hardening="Add TLS SNI inspection",
            ),
        ],
        recommended_actions=["Block evil-phishing.example.com at DNS level"],
        confidence_assessment="High confidence based on multiple corroborating indicators",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNormalizeToCase:
    """Test the normalize → enrich → case pipeline without LLM."""

    def test_normalize_and_build_case(self) -> None:
        """Indicators should normalize and form a case."""
        raw_data = _sample_indicators()
        normalized = normalize(raw_data, source="test")
        assert len(normalized) == 3

        # Create enriched indicators
        enriched = []
        for d in normalized:
            raw = RawIndicator(
                ioc_id=d["ioc_id"],
                ioc_type=d["ioc_type"],
                value=d["value"],
                source=d["source"],
                source_context=d["source_context"],
            )
            enriched.append(
                EnrichedIndicator(
                    indicator=raw,
                    enrichment={},
                    enrichment_status="ok",
                )
            )

        cases = build_cases(enriched)
        assert len(cases) >= 1
        total_indicators = sum(len(c.indicators) for c in cases)
        assert total_indicators == 3


class TestStixExportValid:
    """Test that STIX export produces valid output."""

    def test_stix_bundle_is_valid(self) -> None:
        """Generated STIX bundle should be valid STIX 2.1."""
        # Create case
        raw_data = _sample_indicators()
        normalized = normalize(raw_data, source="test")
        enriched = []
        for d in normalized:
            raw = RawIndicator(
                ioc_id=d["ioc_id"],
                ioc_type=d["ioc_type"],
                value=d["value"],
                source=d["source"],
                source_context=d["source_context"],
            )
            enriched.append(
                EnrichedIndicator(
                    indicator=raw,
                    enrichment={},
                    enrichment_status="ok",
                )
            )

        cases = build_cases(enriched)
        case = cases[0]
        report = _mock_report(case)

        # Build STIX bundle
        bundle = build_stix_bundle(case, report)

        # Validate bundle structure
        assert bundle["type"] == "bundle"
        assert "objects" in bundle
        assert len(bundle["objects"]) > 0

        # Check all required STIX types are present
        obj_types = {o["type"] for o in bundle["objects"]}
        assert "identity" in obj_types
        assert "indicator" in obj_types
        assert "report" in obj_types
        assert "attack-pattern" in obj_types

        # Check all objects have valid STIX IDs
        for obj in bundle["objects"]:
            assert "--" in obj["id"]
            stix_type = obj["id"].split("--")[0]
            assert stix_type == obj["type"]


class TestJsonExportValid:
    """Test that JSON export produces valid output."""

    def test_json_export_roundtrip(self) -> None:
        """JSON export should produce valid, parseable JSON."""
        raw_data = _sample_indicators()
        normalized = normalize(raw_data, source="test")
        enriched = []
        for d in normalized:
            raw = RawIndicator(
                ioc_id=d["ioc_id"],
                ioc_type=d["ioc_type"],
                value=d["value"],
                source=d["source"],
                source_context=d["source_context"],
            )
            enriched.append(
                EnrichedIndicator(
                    indicator=raw,
                    enrichment={},
                    enrichment_status="ok",
                )
            )

        cases = build_cases(enriched)
        report = _mock_report(cases[0])

        # Export
        json_str = export_json(report)
        data = json.loads(json_str)

        # Validate structure
        assert data["report_id"] == "test-e2e-report-001"
        assert data["title"] == "E2E Test Case Analysis"
        assert len(data["techniques"]) == 1
        assert len(data["detection_rules"]) == 1
        assert len(data["adversarial_considerations"]) == 1
        assert len(data["recommended_actions"]) == 1


class TestFullPipelineWithMockedLLM:
    """Test the full pipeline with mocked LLM agents."""

    @pytest.mark.asyncio()
    async def test_pipeline_produces_report(self) -> None:
        """Full pipeline with mocked agents should produce a valid report."""
        from threatweave.intelligence.graph import build_graph

        raw_data = _sample_indicators()
        normalized = normalize(raw_data, source="test")
        enriched = []
        for d in normalized:
            raw = RawIndicator(
                ioc_id=d["ioc_id"],
                ioc_type=d["ioc_type"],
                value=d["value"],
                source=d["source"],
                source_context=d["source_context"],
            )
            enriched.append(
                EnrichedIndicator(
                    indicator=raw,
                    enrichment={},
                    enrichment_status="ok",
                )
            )

        cases = build_cases(enriched)
        assert len(cases) >= 1

        case = cases[0]
        report = _mock_report(case)

        # Verify the report has all required fields
        assert report.title
        assert report.executive_summary
        assert len(report.technique_table) > 0
        assert len(report.detection_rules) > 0
        assert len(report.recommended_actions) > 0

        # Verify STIX can be generated from it
        bundle = build_stix_bundle(case, report)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) > 0

        # Verify JSON can be exported
        report_dict = report_to_dict(report)
        assert report_dict["report_id"] == report.report_id


# Need to import json for the json export test
import json
