"""Hunter agent — generates Sigma detection rules from ATT&CK mappings.

Takes AnalystOutput with technique mappings, generates Sigma rules and
hunt hypotheses using LLM via instructor. Handles validator feedback
for retry loops.
"""

from __future__ import annotations

import logging
from pathlib import Path

import instructor
import litellm

from threatweave.config import get_settings
from threatweave.models.agent_state import AnalystOutput, HunterOutput, ValidationResult
from threatweave.models.case import Case

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "hunter.md"


def _load_system_prompt() -> str:
    """Load the hunter system prompt from markdown file."""
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _build_context(
    case: Case,
    analyst_output: AnalystOutput,
    validator_feedback: ValidationResult | None = None,
) -> str:
    """Build context from analyst output and optional validator feedback."""
    lines: list[str] = []

    # Case indicators summary
    lines.append("## Case Indicators")
    for ei in case.indicators:
        ind = ei.indicator
        lines.append(f"- **{ind.ioc_type}**: `{ind.value}` (source: {ind.source})")
    lines.append("")

    # Analyst output
    lines.append("## Analyst Findings")
    lines.append(f"Case Summary: {analyst_output.case_summary}")
    lines.append("")
    lines.append("### ATT&CK Technique Mappings")
    for mapping in analyst_output.technique_mappings:
        lines.append(
            f"- **{mapping.technique_id}** ({mapping.technique_name}) — "
            f"Tactic: {mapping.tactic}"
        )
        lines.append(f"  Evidence: {mapping.evidence}")
    lines.append("")

    # Validator feedback (for retry loops)
    if validator_feedback and validator_feedback.status == "fail":
        lines.append("## ⚠️ VALIDATOR FEEDBACK — YOU MUST ADDRESS THESE ISSUES")
        lines.append("")
        for issue in validator_feedback.issues:
            lines.append(f"- **[{issue.severity.upper()}] {issue.check}**: {issue.detail}")
        lines.append("")
        lines.append(
            "Fix the issues above. Preserve rules that passed validation. "
            "Only regenerate rules that were flagged."
        )

    return "\n".join(lines)


def run_hunter(
    case: Case,
    analyst_output: AnalystOutput,
    validator_feedback: ValidationResult | None = None,
) -> HunterOutput:
    """Run the Hunter agent.

    Args:
        case: The case being analyzed.
        analyst_output: Output from the Analyst agent.
        validator_feedback: Optional validation issues from a previous attempt.

    Returns:
        HunterOutput with Sigma rules and hunt hypotheses.
    """
    settings = get_settings()

    system_prompt = _load_system_prompt()
    user_message = _build_context(case, analyst_output, validator_feedback)

    logger.info("Calling LLM for Hunter agent (model: %s)", settings.llm_model)
    client = instructor.from_litellm(litellm.completion, mode=instructor.Mode.JSON)

    try:
        result = client.chat.completions.create(
            model=settings.llm_model,
            response_model=HunterOutput,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_retries=2,
            temperature=0.3,

        )
    except Exception:
        logger.exception("Hunter agent LLM call failed")
        raise

    logger.info(
        "Hunter produced %d Sigma rules and %d hunt hypotheses",
        len(result.sigma_rules),
        len(result.hunt_hypotheses),
    )
    return result
