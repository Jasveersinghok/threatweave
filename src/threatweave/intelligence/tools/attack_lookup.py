"""ATT&CK exact-ID lookup tool.

Takes a technique ID (e.g. T1566.001) and returns the full technique
document from the parsed ATT&CK data. Returns None if the ID doesn't exist.
Used by the Validator to verify technique IDs are real.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatweave.config import get_settings

# Cached technique index: technique_id → technique document
_technique_index: dict[str, dict[str, Any]] | None = None


def _load_index() -> dict[str, dict[str, Any]]:
    """Load and cache the technique index from disk."""
    global _technique_index
    if _technique_index is not None:
        return _technique_index

    settings = get_settings()
    path = Path(settings.attack_techniques_file)
    if not path.exists():
        msg = (
            f"ATT&CK techniques file not found at {path}. "
            "Run 'make ingest-attack' first."
        )
        raise FileNotFoundError(msg)

    with open(path, encoding="utf-8") as f:
        techniques: list[dict[str, Any]] = json.load(f)

    _technique_index = {t["technique_id"]: t for t in techniques}
    return _technique_index


def reset_index() -> None:
    """Reset the cached index (useful for testing)."""
    global _technique_index
    _technique_index = None


def lookup_technique(technique_id: str) -> dict[str, Any] | None:
    """Look up a technique by its ATT&CK ID (e.g. T1566.001).

    Args:
        technique_id: The ATT&CK technique ID to look up.

    Returns:
        The full technique document, or None if the ID doesn't exist.
    """
    index = _load_index()
    return index.get(technique_id)


def technique_exists(technique_id: str) -> bool:
    """Check whether a technique ID exists in the ATT&CK dataset."""
    return lookup_technique(technique_id) is not None
