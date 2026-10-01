"""Reporter agent — produces the final structured intelligence report.

Takes validated outputs from all previous agents and synthesizes them
into a FinalReport via LLM.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import instructor
import litellm

from threatweave.config import get_settings
from threatweave.models.agent_state import (
    AnalystOutput,
    FinalReport,
    HunterOutput,
    RedOutput,
    ValidationResult,
)
from threatweave.models.case import Case

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "reporter.md"


def _load_system_prompt() -> str:
    """Load the reporter system prompt from markdown file."""
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _generate_report_id(case_id: str) -> str:
    """Generate a deterministic report UUID from the case ID."""
    namespace = uuid.UUID("a3f1b2c4-d5e6-7890-abcd-ef1234567890")
    return str(uuid.uuid5(namespace, case_id))


def _build_context(
    case: Case,
    analyst_output: AnalystOutput,
    hunter_output: HunterOutput,
    red_output: RedOutput,
    validation_result: ValidationResult,
) -> str:
    """Build full context from all agent outputs."""
    lines: list[str] = []

    # Report metadata
    report_id = _generate_report_id(case.case_id)
    lines.append(f"## Report ID: {report_id}")
    lines.append(f"## Case: {case.case_id}")
    lines.append("")

    # Validation status
    lines.append(f"## Validation Status: {validation_result.status.upper()}")
    if validation_result.issues:
        lines.append("### Unresolved Validation Issues:")
        for issue in validation_result.issues:
            lines.append(f"- [{issue.severity}] {issue.check}: {issue.detail}")
    lines.append("")

    # Case indicators
    lines.append("## Case Indicators (for IOC table)")
    for ei in case.indicators:
        ind = ei.indicator
        lines.append(
            f"- {ind.ioc_type}: `{ind.value}` | source: {ind.source} | "
            f"context: {ind.source_context} | TLP: {ind.tlp}"
        )
    lines.append("")

    # Analyst findings
    lines.append("## Analyst Findings")
    lines.append(f"Case Summary: {analyst_output.case_summary}")
    lines.append(
        f"Threat Assessment: severity={analyst_output.threat_assessment.severity}, "
        f"confidence={analyst_output.threat_assessment.confidence}"
    )
    lines.append(f"Reasoning: {analyst_output.threat_assessment.reasoning}")
    lines.append("")
    lines.append("### Technique Mappings")
    for m in analyst_output.technique_mappings:
        lines.append(
            f"- {m.technique_id} ({m.technique_name}) — {m.tactic} — "
            f"confidence: {m.confidence}"
        )
        lines.append(f"  Evidence: {m.evidence}")
    lines.append("")

    # Hunter output
    lines.append("## Detection Rules")
    for rule in hunter_output.sigma_rules:
        lines.append(f"### {rule.rule_title}")
        lines.append(f"Technique: {rule.technique_id} | Data source: {rule.data_source}")
        lines.append(f"Rationale: {rule.rationale}")
        lines.append("```yaml")
        lines.append(rule.rule_yaml)
        lines.append("```")
        lines.append("")

    # Red Team output
    lines.append("## Adversarial Analysis")
    lines.append(f"Overall: {red_output.overall_assessment}")
    for ea in red_output.evasion_analysis:
        lines.append(
            f"- **{ea.target_rule}**: {ea.evasion_technique} "
            f"(difficulty: {ea.difficulty})"
        )
        lines.append(f"  Hardening: {ea.suggested_hardening}")
    if red_output.coverage_gaps:
        lines.append("")
        lines.append("### Coverage Gaps")
        for gap in red_output.coverage_gaps:
            lines.append(f"- {gap}")

    return "\n".join(lines)


def run_reporter(
    case: Case,
    analyst_output: AnalystOutput,
    hunter_output: HunterOutput,
    red_output: RedOutput,
    validation_result: ValidationResult,
) -> FinalReport:
    """Run the Reporter agent.

    Args:
        case: The case being analyzed.
        analyst_output: Output from the Analyst agent.
        hunter_output: Output from the Hunter agent.
        red_output: Output from the Red Team agent.
        validation_result: Final validation result.

    Returns:
        FinalReport with the complete intelligence report.
    """
    settings = get_settings()

    system_prompt = _load_system_prompt()
    user_message = _build_context(
        case, analyst_output, hunter_output, red_output, validation_result
    )

    # Pre-fill some deterministic fields
    report_id = _generate_report_id(case.case_id)

    logger.info("Calling LLM for Reporter agent (model: %s)", settings.llm_model)
    client = instructor.from_litellm(litellm.completion, mode=instructor.Mode.JSON)

    try:
        result = client.chat.completions.create(
            model=settings.llm_model,
            response_model=FinalReport,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_retries=2,
            temperature=0.2,

        )
    except Exception:
        logger.exception("Reporter agent LLM call failed")
        raise

    # Override deterministic fields
    result.report_id = report_id
    result.validation_status = (
        "pass" if validation_result.status == "pass" else "partial"
    )
    result.validation_issues = validation_result.issues

    logger.info("Reporter produced report: %s", result.title)
    return result
