"""LangGraph multi-agent intelligence pipeline.

Defines the StateGraph with 5 agent nodes, conditional routing for the
Validator→Hunter retry loop, and checkpointing via MemorySaver.

Graph: Analyst → Hunter → Red → Validator → (conditional)
  - Pass → Reporter
  - Fail (iteration < 3) → Hunter (with feedback)
  - Fail (iteration >= 3) → Reporter (with warnings)
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from threatweave.intelligence.agents.analyst import run_analyst
from threatweave.intelligence.agents.hunter import run_hunter
from threatweave.intelligence.agents.red import run_red
from threatweave.intelligence.agents.reporter import run_reporter
from threatweave.intelligence.agents.validator import run_validator
from threatweave.models.agent_state import AgentState
from threatweave.models.case import Case
from threatweave.models.indicators import EnrichedIndicator, RawIndicator, generate_ioc_id

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 3

# Rate limit delay (seconds) between LLM agent calls — needed for free tier
_RATE_LIMIT_DELAY = 20


# ---------------------------------------------------------------------------
# Node functions — each takes AgentState, returns partial state update
# ---------------------------------------------------------------------------

def slow_down_and_rotate_keys() -> None:
    """Rotate keys if multiple are provided."""
    
    keys_str = os.environ.get("GROQ_API_KEYS", "")
    if keys_str:
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        if keys:
            current_key = keys.pop(0)
            keys.append(current_key)
            os.environ["GROQ_API_KEYS"] = ",".join(keys)
            os.environ["GROQ_API_KEY"] = current_key
            logger.info("Rotated GROQ_API_KEY for next agent call")


def analyst_node(state: AgentState) -> dict[str, Any]:
    """Run the Analyst agent."""
    logger.info("=== ANALYST NODE ===")
    slow_down_and_rotate_keys()
    try:
        result = run_analyst(state["case"])
        return {"analyst_output": result}
    except Exception as e:
        logger.exception("Analyst node failed")
        return {"errors": [*state.get("errors", []), f"Analyst error: {e}"]}


def hunter_node(state: AgentState) -> dict[str, Any]:
    """Run the Hunter agent, with optional validator feedback."""
    logger.info("=== HUNTER NODE (iteration %d) ===", state.get("iteration", 0))
    slow_down_and_rotate_keys()
    analyst_output = state.get("analyst_output")
    if analyst_output is None:
        return {"errors": [*state.get("errors", []), "Hunter: no analyst output"]}

    # Pass validator feedback if this is a retry
    validator_feedback = state.get("validation_result")

    try:
        result = run_hunter(
            case=state["case"],
            analyst_output=analyst_output,
            validator_feedback=validator_feedback,
        )
        return {"hunter_output": result}
    except Exception as e:
        logger.exception("Hunter node failed")
        return {"errors": [*state.get("errors", []), f"Hunter error: {e}"]}


def red_node(state: AgentState) -> dict[str, Any]:
    """Run the Red Team agent."""
    logger.info("=== RED TEAM NODE ===")
    slow_down_and_rotate_keys()
    hunter_output = state.get("hunter_output")
    if hunter_output is None:
        return {"errors": [*state.get("errors", []), "Red: no hunter output"]}

    try:
        result = run_red(hunter_output=hunter_output)
        return {"red_output": result}
    except Exception as e:
        logger.exception("Red Team node failed")
        return {"errors": [*state.get("errors", []), f"Red Team error: {e}"]}


def validator_node(state: AgentState) -> dict[str, Any]:
    """Run the Validator (deterministic checks)."""
    logger.info("=== VALIDATOR NODE ===")
    analyst_output = state.get("analyst_output")
    hunter_output = state.get("hunter_output")
    red_output = state.get("red_output")

    if not all([analyst_output, hunter_output, red_output]):
        return {
            "validation_result": None,
            "errors": [*state.get("errors", []), "Validator: missing agent outputs"],
        }

    assert analyst_output is not None
    assert hunter_output is not None
    assert red_output is not None

    result = run_validator(
        analyst_output=analyst_output,
        hunter_output=hunter_output,
        red_output=red_output,
    )

    # Increment iteration counter
    new_iteration = state.get("iteration", 0) + 1
    return {"validation_result": result, "iteration": new_iteration}


def reporter_node(state: AgentState) -> dict[str, Any]:
    """Run the Reporter agent."""
    logger.info("=== REPORTER NODE ===")
    slow_down_and_rotate_keys()
    analyst_output = state.get("analyst_output")
    hunter_output = state.get("hunter_output")
    red_output = state.get("red_output")
    validation_result = state.get("validation_result")

    if not all([analyst_output, hunter_output, red_output]):
        return {"errors": [*state.get("errors", []), "Reporter: missing agent outputs"]}

    assert analyst_output is not None
    assert hunter_output is not None
    assert red_output is not None

    # If validation_result is None (shouldn't happen), create a pass result
    from threatweave.models.agent_state import ValidationResult

    if validation_result is None:
        validation_result = ValidationResult(status="pass", issues=[])

    try:
        result = run_reporter(
            case=state["case"],
            analyst_output=analyst_output,
            hunter_output=hunter_output,
            red_output=red_output,
            validation_result=validation_result,
        )
        return {"report": result}
    except Exception as e:
        logger.exception("Reporter node failed")
        return {"errors": [*state.get("errors", []), f"Reporter error: {e}"]}


# ---------------------------------------------------------------------------
# Routing function for conditional edge from Validator
# ---------------------------------------------------------------------------


def validator_router(state: AgentState) -> str:
    """Route from Validator: pass→reporter, fail→hunter or reporter."""
    validation_result = state.get("validation_result")
    iteration = state.get("iteration", 0)

    if validation_result is None:
        logger.warning("No validation result — routing to reporter")
        return "reporter"

    if validation_result.status == "pass":
        logger.info("Validation PASSED — routing to reporter")
        return "reporter"

    if iteration >= MAX_ITERATIONS:
        logger.warning(
            "Validation FAILED but hit iteration cap (%d) — routing to reporter with warnings",
            MAX_ITERATIONS,
        )
        return "reporter"

    logger.info(
        "Validation FAILED (iteration %d/%d) — routing back to hunter",
        iteration,
        MAX_ITERATIONS,
    )
    return "hunter"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph() -> StateGraph:
    """Build the LangGraph state graph for the intelligence pipeline.

    Returns:
        Compiled StateGraph with checkpointing enabled.
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("analyst", analyst_node)
    graph.add_node("hunter", hunter_node)
    graph.add_node("red", red_node)
    graph.add_node("validator", validator_node)
    graph.add_node("reporter", reporter_node)

    # Set entry point
    graph.set_entry_point("analyst")

    # Linear edges
    graph.add_edge("analyst", "hunter")
    graph.add_edge("hunter", "red")
    graph.add_edge("red", "validator")

    # Conditional edge from validator
    graph.add_conditional_edges(
        "validator",
        validator_router,
        {"reporter": "reporter", "hunter": "hunter"},
    )

    # Reporter is the terminal node
    graph.add_edge("reporter", END)

    return graph


def compile_graph(checkpointer: Any = None) -> Any:
    """Build and compile the graph with optional checkpointing.

    Args:
        checkpointer: LangGraph checkpointer (default: MemorySaver).

    Returns:
        Compiled graph ready for invocation.
    """
    if checkpointer is None:
        checkpointer = MemorySaver()

    graph = build_graph()
    return graph.compile(checkpointer=checkpointer)


async def run_analysis(case: Case) -> AgentState:
    """Run the full intelligence pipeline on a case.

    Args:
        case: The case to analyze.

    Returns:
        Final AgentState with all agent outputs.
    """
    compiled = compile_graph()

    initial_state: AgentState = {
        "case": case,
        "analyst_output": None,
        "hunter_output": None,
        "red_output": None,
        "validation_result": None,
        "report": None,
        "iteration": 0,
        "errors": [],
    }

    config = {"configurable": {"thread_id": case.case_id}}

    logger.info("Starting intelligence pipeline for case %s", case.case_id)
    result: AgentState = compiled.invoke(initial_state, config=config)
    logger.info("Pipeline complete for case %s", case.case_id)

    return result


# ---------------------------------------------------------------------------
# CLI entry point for testing
# ---------------------------------------------------------------------------


def _create_test_case() -> Case:
    """Create a hardcoded test case for end-to-end pipeline testing."""
    indicators = [
        {
            "ioc_type": "domain",
            "value": "evil-phishing.example.com",
            "source": "manual",
            "source_context": (
                "Phishing domain serving credential harvesting"
                " pages targeting corporate email"
            ),
        },
        {
            "ioc_type": "ipv4",
            "value": "198.51.100.42",
            "source": "manual",
            "source_context": "C2 server observed in APT29 campaign, hosting Cobalt Strike beacon",
        },
        {
            "ioc_type": "sha256",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source": "manual",
            "source_context": (
                "Malicious DLL payload dropped by spearphishing"
                " attachment, side-loaded via legitimate application"
            ),
        },
        {
            "ioc_type": "cve",
            "value": "CVE-2024-3400",
            "source": "manual",
            "source_context": (
                "PAN-OS command injection vulnerability exploited"
                " for initial access to perimeter firewall"
            ),
        },
    ]

    enriched_indicators = []
    for ind_data in indicators:
        ioc_id = generate_ioc_id(
            ind_data["ioc_type"], ind_data["value"], ind_data["source"]
        )
        raw = RawIndicator(
            ioc_id=ioc_id,
            ioc_type=ind_data["ioc_type"],  # type: ignore[arg-type]
            value=ind_data["value"],
            source=ind_data["source"],
            source_context=ind_data["source_context"],
        )
        enriched_indicators.append(
            EnrichedIndicator(indicator=raw, enrichment={}, enrichment_status="ok")
        )

    return Case(
        case_id="test-case-apt29-001",
        indicators=enriched_indicators,
        grouping_reason="Manual test case — APT29-style campaign indicators",
        created_at=datetime.now(UTC),
    )


def main() -> None:
    """Entry point for testing: python -m threatweave.intelligence.graph"""
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    case = _create_test_case()
    logger.info("Created test case with %d indicators", len(case.indicators))

    result = asyncio.run(run_analysis(case))

    # Print results
    report = result.get("report")
    if report is not None:
        print("\n" + "=" * 70)
        print(f"REPORT: {report.title}")
        print("=" * 70)
        print(f"\nExecutive Summary:\n{report.executive_summary}")
        print(f"\nTechniques: {len(report.technique_table)}")
        print(f"Detection Rules: {len(report.detection_rules)}")
        print(f"Validation: {report.validation_status}")
        if report.validation_issues:
            print(f"Issues: {len(report.validation_issues)}")
        print("\nRecommended Actions:")
        for action in report.recommended_actions:
            print(f"  - {action}")
    else:
        print("\nNo report generated. Errors:")
        for err in result.get("errors", []):
            print(f"  - {err}")


if __name__ == "__main__":
    main()
