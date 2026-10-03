"""Red Team agent — adversarial critique of detection rules.

Takes HunterOutput with Sigma rules, critiques them from an attacker's
perspective, and suggests hardening. Pure LLM reasoning, no offensive tooling.
"""

from __future__ import annotations

import logging
from pathlib import Path

import instructor
import litellm

from threatweave.config import get_settings
from threatweave.models.agent_state import HunterOutput, RedOutput

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "red.md"


def _load_system_prompt() -> str:
    """Load the red team system prompt from markdown file."""
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _build_context(hunter_output: HunterOutput) -> str:
    """Build context from hunter output for adversarial review."""
    lines: list[str] = []

    lines.append("## Detection Rules to Review")
    lines.append("")
    for i, rule in enumerate(hunter_output.sigma_rules, 1):
        lines.append(f"### Rule {i}: {rule.rule_title}")
        lines.append(f"- Technique: {rule.technique_id}")
        lines.append(f"- Data Source: {rule.data_source}")
        lines.append(f"- Rationale: {rule.rationale}")
        lines.append("```yaml")
        lines.append(rule.rule_yaml)
        lines.append("```")
        lines.append("")

    if hunter_output.hunt_hypotheses:
        lines.append("## Hunt Hypotheses to Review")
        lines.append("")
        for h in hunter_output.hunt_hypotheses:
            lines.append(f"- **{h.hypothesis}** (Data: {h.data_source})")
            lines.append(f"  Query logic: {h.query_logic}")
        lines.append("")

    return "\n".join(lines)


def run_red(hunter_output: HunterOutput) -> RedOutput:
    """Run the Red Team agent.

    Args:
        hunter_output: Output from the Hunter agent.

    Returns:
        RedOutput with evasion analysis, coverage gaps, and assessment.
    """
    settings = get_settings()

    system_prompt = _load_system_prompt()
    user_message = _build_context(hunter_output)

    logger.info("Calling LLM for Red Team agent (model: %s)", settings.llm_model)
    client = instructor.from_litellm(litellm.completion, mode=instructor.Mode.MD_JSON)

    try:
        result = client.chat.completions.create(
            model=settings.llm_model,
            response_model=RedOutput,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_retries=2,
            temperature=0.4,
            max_tokens=2000,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    except Exception:
        logger.exception("Red Team agent LLM call failed")
        raise

    logger.info(
        "Red Team produced %d evasion analyses, %d coverage gaps",
        len(result.evasion_analysis),
        len(result.coverage_gaps),
    )
    return result
