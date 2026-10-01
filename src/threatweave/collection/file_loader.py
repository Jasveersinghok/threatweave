"""File loader — parse JSON and CSV indicator files into RawIndicator lists.

Auto-detects format based on file extension and normalizes all indicators.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from threatweave.collection.normalize import normalize
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)


def load_from_json(path: str | Path) -> list[RawIndicator]:
    """Parse a JSON array of indicators.

    Expected format: array of objects with keys type, value, source, context.

    Args:
        path: Path to the JSON file.

    Returns:
        List of normalized RawIndicator instances.
    """
    path = Path(path)
    logger.info("Loading indicators from JSON: %s", path)

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        msg = f"Expected a JSON array, got {type(data).__name__}"
        raise ValueError(msg)

    normalized = normalize(data, source="file")
    indicators = [
        RawIndicator(
            ioc_id=d["ioc_id"],
            ioc_type=d["ioc_type"],  # type: ignore[arg-type]
            value=d["value"],
            source=d["source"],
            source_context=d["source_context"],
        )
        for d in normalized
    ]
    logger.info("Loaded %d indicators from JSON", len(indicators))
    return indicators


def load_from_csv(path: str | Path) -> list[RawIndicator]:
    """Parse a CSV file with columns: type, value, context.

    Args:
        path: Path to the CSV file.

    Returns:
        List of normalized RawIndicator instances.
    """
    path = Path(path)
    logger.info("Loading indicators from CSV: %s", path)

    raw_data: list[dict[str, str]] = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_data.append(
                {
                    "type": row.get("type", ""),
                    "value": row.get("value", ""),
                    "source": row.get("source", "file"),
                    "context": row.get("context", ""),
                }
            )

    normalized = normalize(raw_data, source="file")
    indicators = [
        RawIndicator(
            ioc_id=d["ioc_id"],
            ioc_type=d["ioc_type"],  # type: ignore[arg-type]
            value=d["value"],
            source=d["source"],
            source_context=d["source_context"],
        )
        for d in normalized
    ]
    logger.info("Loaded %d indicators from CSV", len(indicators))
    return indicators


def load_indicators(path: str | Path) -> list[RawIndicator]:
    """Auto-detect format and load indicators.

    Args:
        path: Path to a .json or .csv file.

    Returns:
        List of normalized RawIndicator instances.
    """
    path = Path(path)
    ext = path.suffix.lower()

    if ext == ".json":
        return load_from_json(path)
    if ext == ".csv":
        return load_from_csv(path)

    msg = f"Unsupported file format: {ext}. Use .json or .csv"
    raise ValueError(msg)
