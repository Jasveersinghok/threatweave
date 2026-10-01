"""ATT&CK STIX 2.1 ingestion — download, parse, and save technique documents.

Downloads the MITRE ATT&CK Enterprise STIX 2.1 bundle, extracts every
attack-pattern object, and saves parsed techniques as JSON.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_attack_bundle(url: str = ATTACK_STIX_URL) -> dict[str, Any]:
    """Download the ATT&CK Enterprise STIX 2.1 bundle."""
    logger.info("Downloading ATT&CK STIX bundle from %s ...", url)
    resp = httpx.get(url, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    bundle: dict[str, Any] = resp.json()
    logger.info(
        "Downloaded bundle with %d objects.", len(bundle.get("objects", []))
    )
    return bundle


def _extract_technique_id(obj: dict[str, Any]) -> str | None:
    """Extract the ATT&CK technique ID (e.g. T1566.001) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            return str(ref["external_id"])
    return None


def _extract_tactics(obj: dict[str, Any]) -> list[str]:
    """Extract tactic names from kill_chain_phases."""
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def _extract_data_sources(obj: dict[str, Any]) -> list[str]:
    """Extract data source names from x_mitre_data_sources."""
    return list(obj.get("x_mitre_data_sources", []))


def _extract_detection(obj: dict[str, Any]) -> str:
    """Extract detection guidance text."""
    return str(obj.get("x_mitre_detection", ""))


def parse_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse all attack-pattern objects from the STIX bundle.

    Filters out revoked and deprecated techniques.

    Returns a list of technique documents with:
        technique_id, name, description, tactics, platforms,
        detection, data_sources, url
    """
    techniques: list[dict[str, Any]] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked or deprecated techniques
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        technique_id = _extract_technique_id(obj)
        if technique_id is None:
            continue

        technique: dict[str, Any] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": _extract_tactics(obj),
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": _extract_detection(obj),
            "data_sources": _extract_data_sources(obj),
            "url": "",
        }

        # Extract ATT&CK URL
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and "url" in ref:
                technique["url"] = ref["url"]
                break

        techniques.append(technique)

    logger.info("Parsed %d techniques from STIX bundle.", len(techniques))
    return techniques


def save_techniques(techniques: list[dict[str, Any]], output_path: str | Path) -> Path:
    """Save parsed techniques to a JSON file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)
    logger.info("Saved %d techniques to %s", len(techniques), output)
    return output


def load_techniques(path: str | Path) -> list[dict[str, Any]]:
    """Load previously parsed techniques from JSON."""
    with open(path, encoding="utf-8") as f:
        techniques: list[dict[str, Any]] = json.load(f)
    return techniques


def ingest(output_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """Full ingestion pipeline: download → parse → save."""
    from threatweave.config import get_settings

    settings = get_settings()
    if output_dir is None:
        output_dir = settings.attack_data_dir

    output_file = Path(output_dir) / "techniques.json"

    bundle = download_attack_bundle()
    techniques = parse_techniques(bundle)
    save_techniques(techniques, output_file)
    return techniques


def main() -> None:
    """Entry point for `make ingest-attack` / `python -m threatweave.knowledge.attack_ingest`."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("Starting ATT&CK knowledge base ingestion...")
    techniques = ingest()
    logger.info("Ingestion complete. %d techniques ready.", len(techniques))

    # Also run embedding after ingestion
    from threatweave.knowledge.embeddings import build_index

    build_index(techniques)
    logger.info("Embedding index built. ATT&CK knowledge base is ready.")


if __name__ == "__main__":
    main()
