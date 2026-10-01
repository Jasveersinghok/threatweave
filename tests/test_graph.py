"""Tests for the LangGraph intelligence pipeline.

Tests with mocked LLM:
- A passing case flows analyst→hunter→red→validator→reporter
- A failing case loops back to hunter
- Iteration cap is respected (max 3 attempts then forced to reporter)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from threatweave.intelligence.graph import (
    MAX_ITERATIONS,
    build_graph,
    compile_graph,
    validator_router,
)
from threatweave.models.agent_state import (
    AgentState,
    AnalystOutput,
    EvasionAnalysis,
    FinalReport,
    HunterOutput,
    HuntHypothesis,
    RedOutput,
    SigmaRule,
    TechniqueMapping,
    ThreatAssessment,
    ValidationIssue,
    ValidationResult,
)
from threatweave.models.case import Case
from threatweave.models.indicators import EnrichedIndicator, RawIndicator, generate_ioc_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_SIGMA_YAML = """title: Test Detection
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


@pytest.fixture()
def test_case() -> Case:
    """Create a minimal test case."""
    ioc_id = generate_ioc_id("domain", "evil.example.com", "manual")
    raw = RawIndicator(
        ioc_id=ioc_id,
        ioc_type="domain",
        value="evil.example.com",
        source="manual",
        source_context="Known phishing domain",
    )
    return Case(
        case_id="test-graph-001",
        indicators=[EnrichedIndicator(indicator=raw, enrichment_status="ok")],
        grouping_reason="Test case",
        created_at=datetime.now(UTC),
    )


@pytest.fixture()
def mock_analyst_output() -> AnalystOutput:
    """Create a mock analyst output with valid technique IDs."""
    return AnalystOutput(
        case_summary="Phishing campaign targeting corporate email",
        threat_assessment=ThreatAssessment(
            severity="high",
            confidence="medium",
            reasoning="Domain serves credential harvesting pages",
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
        infrastructure_notes="Single domain observed",
    )


@pytest.fixture()
def mock_hunter_output() -> HunterOutput:
    """Create a mock hunter output with valid Sigma rules."""
    return HunterOutput(
        sigma_rules=[
            SigmaRule(
                technique_id="T1566.001",
                rule_title="DNS Query to Phishing Domain",
                rule_yaml=VALID_SIGMA_YAML,
                rationale="Detects DNS queries to the phishing domain",
                data_source="DNS logs",
            ),
        ],
        hunt_hypotheses=[
            HuntHypothesis(
                hypothesis="Check email logs for messages from phishing domain",
                data_source="Email gateway",
                query_logic="Filter sender domain = evil.example.com",
            ),
        ],
    )


@pytest.fixture()
def mock_red_output() -> RedOutput:
    """Create a mock red team output."""
    return RedOutput(
        evasion_analysis=[
            EvasionAnalysis(
                target_rule="DNS Query to Phishing Domain",
                evasion_technique="Use DNS over HTTPS",
                difficulty="moderate",
                suggested_hardening="Monitor DoH endpoints",
            ),
        ],
        coverage_gaps=["No post-exploitation detection"],
        overall_assessment="Good initial access coverage, gaps in later stages",
    )


@pytest.fixture()
def mock_report() -> FinalReport:
    """Create a mock final report."""
    return FinalReport(
        report_id="test-report-001",
        title="Threat Intelligence Report: Phishing Campaign",
        executive_summary="A phishing campaign was detected targeting corporate email.",
        detailed_analysis="Detailed analysis content here.",
        recommended_actions=["Block evil.example.com at DNS"],
        confidence_assessment="Medium confidence based on single domain observation.",
    )


# ---------------------------------------------------------------------------
# Tests: Validator routing
# ---------------------------------------------------------------------------


class TestValidatorRouter:
    """Tests for the validator conditional routing logic."""

    def test_pass_routes_to_reporter(self, test_case: Case) -> None:
        """A passing validation should route to reporter."""
        state: AgentState = {
            "case": test_case,
            "analyst_output": None,
            "hunter_output": None,
            "red_output": None,
            "validation_result": ValidationResult(status="pass", issues=[]),
            "report": None,
            "iteration": 1,
            "errors": [],
        }
        assert validator_router(state) == "reporter"

    def test_fail_under_cap_routes_to_hunter(self, test_case: Case) -> None:
        """A failing validation under the iteration cap should route back to hunter."""
        state: AgentState = {
            "case": test_case,
            "analyst_output": None,
            "hunter_output": None,
            "red_output": None,
            "validation_result": ValidationResult(
                status="fail",
                issues=[
                    ValidationIssue(
                        check="test", severity="error", detail="test failure"
                    )
                ],
            ),
            "report": None,
            "iteration": 1,  # Under cap of 3
            "errors": [],
        }
        assert validator_router(state) == "hunter"

    def test_fail_at_cap_routes_to_reporter(self, test_case: Case) -> None:
        """A failing validation at the iteration cap should route to reporter."""
        state: AgentState = {
            "case": test_case,
            "analyst_output": None,
            "hunter_output": None,
            "red_output": None,
            "validation_result": ValidationResult(
                status="fail",
                issues=[
                    ValidationIssue(
                        check="test", severity="error", detail="test failure"
                    )
                ],
            ),
            "report": None,
            "iteration": MAX_ITERATIONS,  # At cap
            "errors": [],
        }
        assert validator_router(state) == "reporter"

    def test_no_result_routes_to_reporter(self, test_case: Case) -> None:
        """Missing validation result should route to reporter as fallback."""
        state: AgentState = {
            "case": test_case,
            "analyst_output": None,
            "hunter_output": None,
            "red_output": None,
            "validation_result": None,
            "report": None,
            "iteration": 0,
            "errors": [],
        }
        assert validator_router(state) == "reporter"


# ---------------------------------------------------------------------------
# Tests: Graph structure
# ---------------------------------------------------------------------------


class TestGraphStructure:
    """Tests for graph construction."""

    def test_graph_builds(self) -> None:
        """Graph should build without errors."""
        graph = build_graph()
        assert graph is not None

    def test_graph_compiles(self) -> None:
        """Graph should compile with checkpointer."""
        compiled = compile_graph()
        assert compiled is not None

    def test_graph_has_all_nodes(self) -> None:
        """Graph should have all 5 agent nodes."""
        graph = build_graph()
        node_names = set(graph.nodes.keys())
        expected = {"analyst", "hunter", "red", "validator", "reporter"}
        assert expected.issubset(node_names), f"Missing nodes: {expected - node_names}"


# ---------------------------------------------------------------------------
# Tests: End-to-end with mocked LLM
# ---------------------------------------------------------------------------


class TestGraphExecution:
    """Tests for graph execution with mocked agents."""

    def test_passing_case_flows_to_reporter(
        self,
        test_case: Case,
        mock_analyst_output: AnalystOutput,
        mock_hunter_output: HunterOutput,
        mock_red_output: RedOutput,
        mock_report: FinalReport,
    ) -> None:
        """A case that passes validation should flow through all 5 agents."""
        with (
            patch(
                "threatweave.intelligence.graph.run_analyst",
                return_value=mock_analyst_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_hunter",
                return_value=mock_hunter_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_red",
                return_value=mock_red_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_reporter",
                return_value=mock_report,
            ),
        ):
            compiled = compile_graph()
            initial_state: AgentState = {
                "case": test_case,
                "analyst_output": None,
                "hunter_output": None,
                "red_output": None,
                "validation_result": None,
                "report": None,
                "iteration": 0,
                "errors": [],
            }
            result = compiled.invoke(
                initial_state,
                config={"configurable": {"thread_id": "test-pass"}},
            )

            # Should have a report
            assert result["report"] is not None
            assert result["report"].title == mock_report.title
            # Validation should pass (real validator runs)
            assert result["validation_result"] is not None
            assert result["validation_result"].status == "pass"

    def test_failing_case_loops_to_hunter(
        self,
        test_case: Case,
        mock_analyst_output: AnalystOutput,
        mock_red_output: RedOutput,
        mock_report: FinalReport,
    ) -> None:
        """A case with bad Sigma rules should loop back to hunter then eventually pass."""
        bad_sigma = "not valid yaml: [[[{"
        bad_hunter = HunterOutput(
            sigma_rules=[
                SigmaRule(
                    technique_id="T1566.001",
                    rule_title="Bad Rule",
                    rule_yaml=bad_sigma,
                    rationale="Test",
                    data_source="DNS",
                ),
            ],
        )
        good_hunter = HunterOutput(
            sigma_rules=[
                SigmaRule(
                    technique_id="T1566.001",
                    rule_title="Fixed Rule",
                    rule_yaml=VALID_SIGMA_YAML,
                    rationale="Fixed test",
                    data_source="DNS",
                ),
            ],
        )

        # First call returns bad output, second returns good
        hunter_call_count = 0

        def mock_hunter_fn(*args: Any, **kwargs: Any) -> HunterOutput:
            nonlocal hunter_call_count
            hunter_call_count += 1
            if hunter_call_count == 1:
                return bad_hunter
            return good_hunter

        with (
            patch(
                "threatweave.intelligence.graph.run_analyst",
                return_value=mock_analyst_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_hunter",
                side_effect=mock_hunter_fn,
            ),
            patch(
                "threatweave.intelligence.graph.run_red",
                return_value=mock_red_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_reporter",
                return_value=mock_report,
            ),
        ):
            compiled = compile_graph()
            initial_state: AgentState = {
                "case": test_case,
                "analyst_output": None,
                "hunter_output": None,
                "red_output": None,
                "validation_result": None,
                "report": None,
                "iteration": 0,
                "errors": [],
            }
            result = compiled.invoke(
                initial_state,
                config={"configurable": {"thread_id": "test-retry"}},
            )

            # Hunter should have been called at least twice
            assert hunter_call_count >= 2
            # Should still produce a report
            assert result["report"] is not None

    def test_iteration_cap_respected(
        self,
        test_case: Case,
        mock_analyst_output: AnalystOutput,
        mock_red_output: RedOutput,
        mock_report: FinalReport,
    ) -> None:
        """After MAX_ITERATIONS, should route to reporter even if validation fails."""
        bad_hunter = HunterOutput(
            sigma_rules=[
                SigmaRule(
                    technique_id="T1566.001",
                    rule_title="Always Bad Rule",
                    rule_yaml="not valid yaml: [[[{",
                    rationale="Test",
                    data_source="DNS",
                ),
            ],
        )

        hunter_call_count = 0

        def mock_hunter_always_bad(*args: Any, **kwargs: Any) -> HunterOutput:
            nonlocal hunter_call_count
            hunter_call_count += 1
            return bad_hunter

        with (
            patch(
                "threatweave.intelligence.graph.run_analyst",
                return_value=mock_analyst_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_hunter",
                side_effect=mock_hunter_always_bad,
            ),
            patch(
                "threatweave.intelligence.graph.run_red",
                return_value=mock_red_output,
            ),
            patch(
                "threatweave.intelligence.graph.run_reporter",
                return_value=mock_report,
            ),
        ):
            compiled = compile_graph()
            initial_state: AgentState = {
                "case": test_case,
                "analyst_output": None,
                "hunter_output": None,
                "red_output": None,
                "validation_result": None,
                "report": None,
                "iteration": 0,
                "errors": [],
            }
            result = compiled.invoke(
                initial_state,
                config={"configurable": {"thread_id": "test-cap"}},
            )

            # Hunter should be called exactly MAX_ITERATIONS times
            assert hunter_call_count == MAX_ITERATIONS
            # Should still produce a report (forced through)
            assert result["report"] is not None
