"""Tests for the Validator agent — all deterministic checks.

Tests:
- Valid ATT&CK ID passes, fake ID fails
- Valid Sigma YAML passes, invalid YAML fails
- Empty evidence fails
- Technique-tactic alignment check
- Empty sections detection
- Full validation with good and bad inputs
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from threatweave.intelligence.agents.validator import (
    _check_evidence_present,
    _check_no_empty_sections,
    _check_sigma_rules_parse,
    _check_technique_ids,
    _check_technique_tactic_alignment,
    run_validator,
)
from threatweave.models.agent_state import (
    AnalystOutput,
    EvasionAnalysis,
    HunterOutput,
    HuntHypothesis,
    RedOutput,
    SigmaRule,
    TechniqueMapping,
    ThreatAssessment,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Fixtures: Good and bad agent outputs for testing
# ---------------------------------------------------------------------------

VALID_SIGMA_YAML = """title: Test Rule
status: experimental
logsource:
    category: dns
    product: windows
detection:
    selection:
        QueryName: evil.example.com
    condition: selection
level: high
"""

INVALID_SIGMA_YAML = """title: Bad Rule
this is: not: valid: yaml: [[[
"""

MALFORMED_SIGMA_YAML = """title: Missing Fields Rule
description: This rule is missing logsource and detection
level: high
"""


@pytest.fixture()
def good_analyst_output() -> AnalystOutput:
    """A well-formed analyst output with valid technique IDs."""
    return AnalystOutput(
        case_summary="Test case involving phishing and C2 activity",
        threat_assessment=ThreatAssessment(
            severity="high",
            confidence="medium",
            reasoning="Multiple indicators suggest targeted campaign",
        ),
        technique_mappings=[
            TechniqueMapping(
                technique_id="T1566.001",
                technique_name="Phishing: Spearphishing Attachment",
                tactic="initial-access",
                evidence="Domain evil.example.com serves phishing pages",
                confidence="high",
            ),
        ],
        infrastructure_notes="Shared hosting observed",
    )


@pytest.fixture()
def bad_analyst_output() -> AnalystOutput:
    """An analyst output with a fake technique ID and missing evidence."""
    return AnalystOutput(
        case_summary="Test case",
        threat_assessment=ThreatAssessment(
            severity="high",
            confidence="low",
            reasoning="Some reasoning",
        ),
        technique_mappings=[
            TechniqueMapping(
                technique_id="T9999.999",
                technique_name="Fake Technique",
                tactic="initial-access",
                evidence="Some evidence",
                confidence="low",
            ),
            TechniqueMapping(
                technique_id="T1566.001",
                technique_name="Phishing: Spearphishing Attachment",
                tactic="initial-access",
                evidence="",  # Empty evidence!
                confidence="medium",
            ),
        ],
    )


@pytest.fixture()
def good_hunter_output() -> HunterOutput:
    """A well-formed hunter output with valid Sigma rules."""
    return HunterOutput(
        sigma_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="DNS Query to Known Phishing Domain",
                rule_yaml=VALID_SIGMA_YAML,
                rationale="Detects DNS resolution of the malicious domain",
                data_source="DNS logs",
            ),
        ],
        hunt_hypotheses=[
            HuntHypothesis(
                hypothesis="Look for email attachments from phishing domain",
                data_source="Email gateway logs",
                query_logic="Filter by sender domain matching evil.example.com",
            ),
        ],
    )


@pytest.fixture()
def bad_hunter_output() -> HunterOutput:
    """A hunter output with invalid Sigma YAML."""
    return HunterOutput(
        sigma_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="Bad YAML Rule",
                rule_yaml=INVALID_SIGMA_YAML,
                rationale="Test",
                data_source="DNS logs",
            ),
            SigmaRule(
                technique_id="T1566.001",
                rule_title="Missing Fields Rule",
                rule_yaml=MALFORMED_SIGMA_YAML,
                rationale="Test",
                data_source="DNS logs",
            ),
        ],
    )


@pytest.fixture()
def good_red_output() -> RedOutput:
    """A well-formed red team output."""
    return RedOutput(
        evasion_analysis=[
            EvasionAnalysis(
                target_rule="DNS Query to Known Phishing Domain",
                evasion_technique="Use DNS over HTTPS to bypass monitoring",
                difficulty="moderate",
                suggested_hardening="Monitor for DoH traffic patterns",
            ),
        ],
        coverage_gaps=["No detection for lateral movement"],
        overall_assessment="Detection covers initial access but not post-exploitation",
    )


@pytest.fixture()
def empty_red_output() -> RedOutput:
    """A red team output with empty sections."""
    return RedOutput(
        evasion_analysis=[],
        coverage_gaps=[],
        overall_assessment="",
    )


# ---------------------------------------------------------------------------
# Tests: Individual checks
# ---------------------------------------------------------------------------


class TestTechniqueIdCheck:
    """Tests for ATT&CK technique ID validation."""

    def test_valid_id_passes(self, good_analyst_output: AnalystOutput) -> None:
        """T1566.001 is a real ATT&CK technique and should pass."""
        issues = _check_technique_ids(good_analyst_output)
        assert len(issues) == 0

    def test_fake_id_fails(self, bad_analyst_output: AnalystOutput) -> None:
        """T9999.999 is not a real technique and should fail."""
        issues = _check_technique_ids(bad_analyst_output)
        assert len(issues) >= 1
        assert any("T9999.999" in issue.detail for issue in issues)
        assert all(issue.check == "attack_id_exists" for issue in issues)


class TestTacticAlignment:
    """Tests for technique-tactic alignment."""

    def test_correct_tactic_passes(self, good_analyst_output: AnalystOutput) -> None:
        """T1566.001 mapped to initial-access should pass."""
        issues = _check_technique_tactic_alignment(good_analyst_output)
        assert len(issues) == 0

    def test_wrong_tactic_warns(self) -> None:
        """T1566.001 mapped to 'lateral-movement' should warn."""
        analyst = AnalystOutput(
            case_summary="Test",
            threat_assessment=ThreatAssessment(
                severity="high", confidence="high", reasoning="test"
            ),
            technique_mappings=[
                TechniqueMapping(
                    technique_id="T1566.001",
                    technique_name="Phishing",
                    tactic="lateral-movement",  # Wrong tactic!
                    evidence="some evidence",
                    confidence="high",
                ),
            ],
        )
        issues = _check_technique_tactic_alignment(analyst)
        assert len(issues) >= 1
        assert any(issue.check == "technique_tactic_alignment" for issue in issues)


class TestEvidenceCheck:
    """Tests for evidence presence validation."""

    def test_evidence_present_passes(self, good_analyst_output: AnalystOutput) -> None:
        """Mappings with evidence should pass."""
        issues = _check_evidence_present(good_analyst_output)
        assert len(issues) == 0

    def test_empty_evidence_fails(self, bad_analyst_output: AnalystOutput) -> None:
        """Mappings with empty evidence should fail."""
        issues = _check_evidence_present(bad_analyst_output)
        assert len(issues) >= 1
        assert any(issue.check == "evidence_present" for issue in issues)


class TestSigmaCheck:
    """Tests for Sigma rule parsing validation."""

    def test_valid_sigma_passes(self, good_hunter_output: HunterOutput) -> None:
        """Well-formed Sigma YAML should pass."""
        issues = _check_sigma_rules_parse(good_hunter_output)
        assert len(issues) == 0

    def test_invalid_yaml_fails(self, bad_hunter_output: HunterOutput) -> None:
        """Malformed YAML should fail."""
        issues = _check_sigma_rules_parse(bad_hunter_output)
        assert len(issues) >= 1
        error_checks = {i.check for i in issues}
        assert "sigma_yaml_valid" in error_checks or "sigma_required_fields" in error_checks


class TestEmptySections:
    """Tests for empty section detection."""

    def test_full_output_passes(
        self,
        good_analyst_output: AnalystOutput,
        good_hunter_output: HunterOutput,
        good_red_output: RedOutput,
    ) -> None:
        """Non-empty outputs should not trigger warnings."""
        issues = _check_no_empty_sections(
            good_analyst_output, good_hunter_output, good_red_output
        )
        assert len(issues) == 0

    def test_empty_sections_warns(
        self,
        good_analyst_output: AnalystOutput,
        good_hunter_output: HunterOutput,
        empty_red_output: RedOutput,
    ) -> None:
        """Empty red output sections should trigger warnings."""
        issues = _check_no_empty_sections(
            good_analyst_output, good_hunter_output, empty_red_output
        )
        assert len(issues) >= 1


# ---------------------------------------------------------------------------
# Tests: Full validation
# ---------------------------------------------------------------------------


class TestFullValidation:
    """Tests for the complete validation pipeline."""

    def test_good_outputs_pass(
        self,
        good_analyst_output: AnalystOutput,
        good_hunter_output: HunterOutput,
        good_red_output: RedOutput,
    ) -> None:
        """Valid outputs should produce a 'pass' result."""
        result = run_validator(good_analyst_output, good_hunter_output, good_red_output)
        assert result.status == "pass"

    def test_bad_outputs_fail(
        self,
        bad_analyst_output: AnalystOutput,
        bad_hunter_output: HunterOutput,
        good_red_output: RedOutput,
    ) -> None:
        """Invalid outputs should produce a 'fail' result with issues."""
        result = run_validator(bad_analyst_output, bad_hunter_output, good_red_output)
        assert result.status == "fail"
        assert len(result.issues) >= 2  # At least fake ID + empty evidence
