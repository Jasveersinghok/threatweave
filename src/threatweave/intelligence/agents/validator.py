"""Validator agent — deterministic quality gate for agent outputs.

NOT an LLM agent. Runs concrete, testable checks on the combined output
from Analyst, Hunter, and Red Team agents. Catches hallucinated technique IDs,
malformed Sigma rules, missing evidence, and schema violations.
"""

from __future__ import annotations

import logging
from typing import Literal

import yaml

from threatweave.intelligence.tools.attack_lookup import lookup_technique
from threatweave.models.agent_state import (
    AnalystOutput,
    HunterOutput,
    RedOutput,
    ValidationIssue,
    ValidationResult,
)

logger = logging.getLogger(__name__)


def _check_technique_ids(analyst_output: AnalystOutput) -> list[ValidationIssue]:
    """Check that all mapped technique IDs exist in the ATT&CK dataset."""
    issues: list[ValidationIssue] = []
    for mapping in analyst_output.technique_mappings:
        technique = lookup_technique(mapping.technique_id)
        if technique is None:
            issues.append(
                ValidationIssue(
                    check="attack_id_exists",
                    severity="error",
                    detail=(
                        f"Technique ID '{mapping.technique_id}' does not exist "
                        f"in the ATT&CK dataset."
                    ),
                )
            )
    return issues


def _check_technique_tactic_alignment(
    analyst_output: AnalystOutput,
) -> list[ValidationIssue]:
    """Check that techniques are listed under the correct tactic."""
    issues: list[ValidationIssue] = []
    for mapping in analyst_output.technique_mappings:
        technique = lookup_technique(mapping.technique_id)
        if technique is None:
            continue  # Already caught by _check_technique_ids
        # Normalize tactic names (ATT&CK uses hyphens, prompts may use spaces)
        valid_tactics = {t.replace("-", " ").lower() for t in technique.get("tactics", [])}
        mapped_tactic = mapping.tactic.replace("-", " ").lower()
        if valid_tactics and mapped_tactic not in valid_tactics:
            issues.append(
                ValidationIssue(
                    check="technique_tactic_alignment",
                    severity="warning",
                    detail=(
                        f"Technique {mapping.technique_id} mapped to tactic "
                        f"'{mapping.tactic}', but valid tactics are: "
                        f"{', '.join(technique.get('tactics', []))}"
                    ),
                )
            )
    return issues


def _check_evidence_present(analyst_output: AnalystOutput) -> list[ValidationIssue]:
    """Check that every technique mapping has non-empty evidence."""
    issues: list[ValidationIssue] = []
    for mapping in analyst_output.technique_mappings:
        if not mapping.evidence or not mapping.evidence.strip():
            issues.append(
                ValidationIssue(
                    check="evidence_present",
                    severity="error",
                    detail=(
                        f"Technique {mapping.technique_id} ({mapping.technique_name}) "
                        f"has no evidence citation."
                    ),
                )
            )
    return issues


def _check_sigma_rules_parse(hunter_output: HunterOutput) -> list[ValidationIssue]:
    """Check that all Sigma rules parse successfully with pySigma."""
    issues: list[ValidationIssue] = []

    for rule in hunter_output.sigma_rules:
        # First check it's valid YAML
        try:
            parsed = yaml.safe_load(rule.rule_yaml)
        except yaml.YAMLError as e:
            issues.append(
                ValidationIssue(
                    check="sigma_yaml_valid",
                    severity="error",
                    detail=f"Rule '{rule.rule_title}': Invalid YAML — {e}",
                )
            )
            continue

        if not isinstance(parsed, dict):
            issues.append(
                ValidationIssue(
                    check="sigma_yaml_valid",
                    severity="error",
                    detail=f"Rule '{rule.rule_title}': YAML did not parse to a dict.",
                )
            )
            continue

        # Check required Sigma fields
        required_fields = {"title", "logsource", "detection"}
        missing = required_fields - set(parsed.keys())
        if missing:
            issues.append(
                ValidationIssue(
                    check="sigma_required_fields",
                    severity="error",
                    detail=(
                        f"Rule '{rule.rule_title}': Missing required Sigma fields: "
                        f"{', '.join(sorted(missing))}"
                    ),
                )
            )
            continue

        # Try parsing with pySigma for deeper validation
        try:
            from sigma.rule import SigmaRule

            SigmaRule.from_yaml(rule.rule_yaml)
        except Exception as e:
            issues.append(
                ValidationIssue(
                    check="sigma_parse",
                    severity="error",
                    detail=f"Rule '{rule.rule_title}': pySigma parse error — {e}",
                )
            )

    return issues


def _check_no_empty_sections(
    analyst_output: AnalystOutput,
    hunter_output: HunterOutput,
    red_output: RedOutput,
) -> list[ValidationIssue]:
    """Check for lazy/empty agent outputs."""
    issues: list[ValidationIssue] = []

    if not analyst_output.case_summary or not analyst_output.case_summary.strip():
        issues.append(
            ValidationIssue(
                check="no_empty_sections",
                severity="error",
                detail="Analyst case_summary is empty.",
            )
        )

    if not analyst_output.technique_mappings:
        issues.append(
            ValidationIssue(
                check="no_empty_sections",
                severity="warning",
                detail="Analyst produced no technique mappings.",
            )
        )

    if not hunter_output.sigma_rules:
        issues.append(
            ValidationIssue(
                check="no_empty_sections",
                severity="warning",
                detail="Hunter produced no Sigma rules.",
            )
        )

    if not red_output.evasion_analysis:
        issues.append(
            ValidationIssue(
                check="no_empty_sections",
                severity="warning",
                detail="Red Team produced no evasion analysis.",
            )
        )

    if not red_output.overall_assessment or not red_output.overall_assessment.strip():
        issues.append(
            ValidationIssue(
                check="no_empty_sections",
                severity="warning",
                detail="Red Team overall_assessment is empty.",
            )
        )

    return issues


def run_validator(
    analyst_output: AnalystOutput,
    hunter_output: HunterOutput,
    red_output: RedOutput,
) -> ValidationResult:
    """Run all deterministic validation checks.

    Checks:
    1. ATT&CK ID exists (lookup against ingested dataset)
    2. Technique-tactic alignment (ATT&CK dataset lookup)
    3. Evidence present (string check)
    4. Sigma rules parse (pySigma parser)
    5. No empty sections (deterministic)

    Args:
        analyst_output: Output from the Analyst agent.
        hunter_output: Output from the Hunter agent.
        red_output: Output from the Red Team agent.

    Returns:
        ValidationResult with pass/fail status and list of issues.
    """
    logger.info("Running deterministic validation checks...")
    all_issues: list[ValidationIssue] = []

    # Run all checks
    all_issues.extend(_check_technique_ids(analyst_output))
    all_issues.extend(_check_technique_tactic_alignment(analyst_output))
    all_issues.extend(_check_evidence_present(analyst_output))
    all_issues.extend(_check_sigma_rules_parse(hunter_output))
    all_issues.extend(_check_no_empty_sections(analyst_output, hunter_output, red_output))

    # Determine overall status
    has_errors = any(issue.severity == "error" for issue in all_issues)
    status: Literal["pass", "fail"] = "fail" if has_errors else "pass"

    logger.info(
        "Validation %s: %d issues (%d errors, %d warnings)",
        status,
        len(all_issues),
        sum(1 for i in all_issues if i.severity == "error"),
        sum(1 for i in all_issues if i.severity == "warning"),
    )

    return ValidationResult(status=status, issues=all_issues)
