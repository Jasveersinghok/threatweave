"""Agent output schemas and LangGraph state definition.

Contains all structured output models for the 5-agent pipeline
and the TypedDict used as LangGraph state.
"""

from __future__ import annotations

from typing import Literal, TypedDict

from pydantic import BaseModel, Field

from threatweave.models.case import Case

# ---------------------------------------------------------------------------
# Agent 1: Analyst
# ---------------------------------------------------------------------------

class ThreatAssessment(BaseModel):
    """Threat severity and confidence assessment."""

    severity: Literal["high", "medium", "low"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str


class TechniqueMapping(BaseModel):
    """A single ATT&CK technique mapping with evidence."""

    technique_id: str = Field(description="e.g. T1566.001")
    technique_name: str
    tactic: str
    evidence: str = Field(description="Evidence linking indicator(s) to this technique")
    confidence: Literal["high", "medium", "low"]


class AnalystOutput(BaseModel):
    """Structured output from the Analyst agent."""

    case_summary: str = Field(description="What these indicators suggest as a whole")
    threat_assessment: ThreatAssessment
    technique_mappings: list[TechniqueMapping] = Field(default_factory=list)
    infrastructure_notes: str = Field(
        default="",
        description="Shared hosting, common ASN patterns, etc.",
    )


# ---------------------------------------------------------------------------
# Agent 2: Hunter
# ---------------------------------------------------------------------------

class SigmaRule(BaseModel):
    """A single Sigma detection rule."""

    technique_id: str
    rule_title: str
    rule_yaml: str = Field(description="Complete Sigma rule in YAML format")
    rationale: str
    data_source: str


class HuntHypothesis(BaseModel):
    """A threat hunting hypothesis."""

    hypothesis: str
    data_source: str
    query_logic: str


class HunterOutput(BaseModel):
    """Structured output from the Hunter agent."""

    sigma_rules: list[SigmaRule] = Field(default_factory=list)
    hunt_hypotheses: list[HuntHypothesis] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 3: Red Team
# ---------------------------------------------------------------------------

class EvasionAnalysis(BaseModel):
    """Analysis of how an attacker could evade a specific detection rule."""

    target_rule: str
    evasion_technique: str
    difficulty: Literal["trivial", "moderate", "difficult"]
    suggested_hardening: str


class RedOutput(BaseModel):
    """Structured output from the Red Team agent."""

    evasion_analysis: list[EvasionAnalysis] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    overall_assessment: str = Field(default="")


# ---------------------------------------------------------------------------
# Agent 4: Validator
# ---------------------------------------------------------------------------

class ValidationIssue(BaseModel):
    """A single validation issue found by the Validator."""

    check: str = Field(description="Name of the check that failed")
    severity: Literal["error", "warning"]
    detail: str


class ValidationResult(BaseModel):
    """Structured output from the Validator agent."""

    status: Literal["pass", "fail"]
    issues: list[ValidationIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 5: Reporter
# ---------------------------------------------------------------------------

class FinalReport(BaseModel):
    """Structured final intelligence report."""

    report_id: str = Field(description="Deterministic UUID")
    title: str
    tlp: str = Field(default="TLP:CLEAR")
    executive_summary: str
    detailed_analysis: str
    technique_table: list[TechniqueMapping] = Field(default_factory=list)
    detection_rules: list[SigmaRule] = Field(default_factory=list)
    adversarial_considerations: list[EvasionAnalysis] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    confidence_assessment: str = Field(default="")
    ioc_table: list[dict] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    validation_status: Literal["pass", "partial"] = Field(default="pass")
    validation_issues: list[ValidationIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# LangGraph State
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """LangGraph state schema for the multi-agent intelligence pipeline."""

    case: Case
    analyst_output: AnalystOutput | None
    hunter_output: HunterOutput | None
    red_output: RedOutput | None
    validation_result: ValidationResult | None
    report: FinalReport | None
    iteration: int
    errors: list[str]
