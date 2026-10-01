"""STIX 2.1 export — build STIX Bundle from a completed case report.

Creates:
- Identity (ThreatWeave)
- TLP marking definition
- Indicator objects for each IOC (with STIX pattern)
- Vulnerability objects for CVEs
- AttackPattern objects for mapped techniques
- Relationship objects (indicator → attack-pattern)
- Report object containing the final report text

All object IDs use UUIDv5 for determinism.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import stix2

from threatweave.models.agent_state import FinalReport
from threatweave.models.case import Case

logger = logging.getLogger(__name__)

# Deterministic namespace for UUIDv5
_NAMESPACE = uuid.UUID("b7e8d4a1-2c3f-4e5a-9b8c-d1e2f3a4b5c6")


def _deterministic_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX ID using UUIDv5."""
    uid = uuid.uuid5(_NAMESPACE, f"{stix_type}:{seed}")
    return f"{stix_type}--{uid}"


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    """Convert an IOC to a STIX 2.1 pattern string."""
    patterns: dict[str, str] = {
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "cve": f"[vulnerability:name = '{value}']",
    }
    return patterns.get(ioc_type, f"[x-unknown:value = '{value}']")


def build_stix_bundle(
    case: Case,
    report: FinalReport,
) -> dict[str, Any]:
    """Build a STIX 2.1 Bundle from a completed case and report.

    Args:
        case: The analyzed case with indicators.
        report: The final intelligence report.

    Returns:
        Serialized STIX 2.1 Bundle as a dict.
    """
    objects: list[Any] = []

    # --- Identity ---
    identity = stix2.Identity(
        id=_deterministic_id("identity", "threatweave"),
        name="ThreatWeave",
        description="Multi-Agent CTI Analysis System",
        identity_class="system",
    )
    objects.append(identity)

    # --- TLP Marking (use STIX 2.1 predefined TLP:WHITE) ---
    tlp_marking = stix2.MarkingDefinition(
        id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        name="TLP:WHITE",
        definition_type="tlp",
        definition=stix2.TLPMarking(tlp="white"),
        created="2017-01-20T00:00:00.000Z",
    )

    # --- Indicator objects ---
    indicator_ids: dict[str, str] = {}  # ioc_value → stix_id
    for ei in case.indicators:
        ind = ei.indicator
        stix_id = _deterministic_id("indicator", f"{ind.ioc_type}:{ind.value}")
        indicator_ids[ind.value] = stix_id

        stix_indicator = stix2.Indicator(
            id=stix_id,
            name=f"{ind.ioc_type}: {ind.value}",
            description=ind.source_context or f"{ind.ioc_type} indicator",
            pattern=_ioc_to_stix_pattern(ind.ioc_type, ind.value),
            pattern_type="stix",
            valid_from=ind.observed_at,
            created_by_ref=identity.id,
            object_marking_refs=[tlp_marking.id],
            labels=[ind.ioc_type],
        )
        objects.append(stix_indicator)

    # --- Vulnerability objects for CVEs ---
    vuln_ids: dict[str, str] = {}
    for ei in case.indicators:
        if ei.indicator.ioc_type == "cve":
            cve_id = ei.indicator.value.upper()
            stix_id = _deterministic_id("vulnerability", cve_id)
            vuln_ids[cve_id] = stix_id

            nvd_data = ei.enrichment.get("nvd", {})
            description = nvd_data.get(
                "description", f"Vulnerability {cve_id}"
            )

            vuln = stix2.Vulnerability(
                id=stix_id,
                name=cve_id,
                description=description[:500],
                created_by_ref=identity.id,
                external_references=[
                    stix2.ExternalReference(
                        source_name="cve",
                        external_id=cve_id,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    )
                ],
            )
            objects.append(vuln)

    # --- AttackPattern objects for mapped techniques ---
    technique_ids: dict[str, str] = {}  # technique_id → stix_id
    for mapping in report.technique_table:
        tid = mapping.technique_id
        stix_id = _deterministic_id("attack-pattern", tid)
        technique_ids[tid] = stix_id

        ap = stix2.AttackPattern(
            id=stix_id,
            name=mapping.technique_name,
            description=(
                f"Tactic: {mapping.tactic}\n"
                f"Evidence: {mapping.evidence}\n"
                f"Confidence: {mapping.confidence}"
            ),
            created_by_ref=identity.id,
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=tid,
                    url=(
                        "https://attack.mitre.org/techniques/"
                        + tid.replace(".", "/")
                    ),
                )
            ],
        )
        objects.append(ap)

    # --- Relationship objects ---
    for mapping in report.technique_table:
        tid = mapping.technique_id
        ap_id = technique_ids.get(tid)
        if ap_id is None:
            continue

        # Link each indicator to the attack pattern
        for ei in case.indicators:
            ind_stix_id = indicator_ids.get(ei.indicator.value)
            if ind_stix_id is None:
                continue

            rel_id = _deterministic_id(
                "relationship",
                f"{ind_stix_id}:indicates:{ap_id}",
            )
            rel = stix2.Relationship(
                id=rel_id,
                relationship_type="indicates",
                source_ref=ind_stix_id,
                target_ref=ap_id,
                created_by_ref=identity.id,
            )
            objects.append(rel)

    # --- Report object ---
    report_stix_id = _deterministic_id("report", report.report_id)
    report_obj = stix2.Report(
        id=report_stix_id,
        name=report.title,
        description=report.executive_summary,
        published=case.created_at,
        created_by_ref=identity.id,
        object_refs=[o.id for o in objects],
        object_marking_refs=[tlp_marking.id],
        labels=["threat-report"],
    )
    objects.append(report_obj)

    # --- Bundle ---
    bundle = stix2.Bundle(
        objects=objects,
    )

    logger.info(
        "Built STIX bundle with %d objects for report %s",
        len(objects),
        report.report_id,
    )

    return dict(bundle)
