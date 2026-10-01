"""JSON report export — convert FinalReport to a clean JSON structure.

Produces a UI-friendly JSON object from the FinalReport Pydantic model.
"""

from __future__ import annotations

import json
from typing import Any

from threatweave.models.agent_state import FinalReport


def report_to_dict(report: FinalReport) -> dict[str, Any]:
    """Convert a FinalReport to a clean dictionary.

    Args:
        report: The final intelligence report.

    Returns:
        Dict suitable for JSON serialization and UI rendering.
    """
    return {
        "report_id": report.report_id,
        "title": report.title,
        "tlp": report.tlp,
        "executive_summary": report.executive_summary,
        "detailed_analysis": report.detailed_analysis,
        "techniques": [
            {
                "technique_id": t.technique_id,
                "name": t.technique_name,
                "tactic": t.tactic,
                "evidence": t.evidence,
                "confidence": t.confidence,
            }
            for t in report.technique_table
        ],
        "detection_rules": [
            {
                "technique_id": r.technique_id,
                "title": r.rule_title,
                "yaml": r.rule_yaml,
                "rationale": r.rationale,
                "data_source": r.data_source,
            }
            for r in report.detection_rules
        ],
        "adversarial_considerations": [
            {
                "target_rule": a.target_rule,
                "evasion_technique": a.evasion_technique,
                "difficulty": a.difficulty,
                "suggested_hardening": a.suggested_hardening,
            }
            for a in report.adversarial_considerations
        ],
        "recommended_actions": report.recommended_actions,
        "confidence_assessment": report.confidence_assessment,
        "ioc_table": report.ioc_table,
        "references": report.references,
        "validation": {
            "status": report.validation_status,
            "issues": [
                {
                    "check": i.check,
                    "severity": i.severity,
                    "detail": i.detail,
                }
                for i in report.validation_issues
            ],
        },
    }


def export_json(report: FinalReport, path: str | None = None) -> str:
    """Export FinalReport to JSON.

    Args:
        report: The final intelligence report.
        path: Optional file path to write to.

    Returns:
        JSON string.
    """
    data = report_to_dict(report)
    json_str = json.dumps(data, indent=2, default=str)

    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
