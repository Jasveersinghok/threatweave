"""BM25 keyword-based retrieval for ATT&CK techniques.

Provides exact keyword matching to complement dense vector search.
BM25 excels at finding techniques when the query contains specific
ATT&CK terms like 'supply chain', 'scheduled task', 'command and control'.
"""
from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cached BM25 index so we don't rebuild every call
_bm25_index = None
_bm25_corpus: list[dict] = []


def _tokenize(text: str) -> list[str]:
    """Simple tokenizer: lowercase, split on non-alphanumeric."""
    text = text.lower()
    return re.findall(r'[a-z0-9]+', text)


def _build_bm25_index(techniques_file: str):
    """Build or return cached BM25 index over technique names + descriptions."""
    global _bm25_index, _bm25_corpus
    if _bm25_index is not None:
        return _bm25_index, _bm25_corpus

    from rank_bm25 import BM25Okapi

    with open(techniques_file, encoding="utf-8") as f:
        techniques = json.load(f)

    _bm25_corpus = techniques
    # Index = technique name + description + tactic names
    tokenized_corpus = []
    for t in techniques:
        doc = f"{t['technique_id']} {t['name']} {' '.join(t.get('tactics', []))} {t.get('description', '')}"
        tokenized_corpus.append(_tokenize(doc))

    _bm25_index = BM25Okapi(tokenized_corpus)
    logger.info("BM25 index built for %d techniques", len(techniques))
    return _bm25_index, _bm25_corpus


def bm25_search(query: str, techniques_file: str, top_k: int = 10) -> list[dict[str, Any]]:
    """BM25 keyword search over ATT&CK techniques.

    Args:
        query: Natural language query string.
        techniques_file: Path to techniques JSON.
        top_k: Number of results to return.

    Returns:
        List of technique dicts with bm25_score field.
    """
    bm25, corpus = _build_bm25_index(techniques_file)
    tokens = _tokenize(query)
    scores = bm25.get_scores(tokens)

    # Pair scores with techniques and sort
    scored = sorted(
        [(score, i) for i, score in enumerate(scores)],
        reverse=True
    )

    results = []
    for score, idx in scored[:top_k]:
        if score <= 0:
            break
        t = corpus[idx]
        results.append({
            "technique_id": t.get("technique_id", ""),
            "name": t.get("name", ""),
            "tactics": t.get("tactics", []),
            "platforms": t.get("platforms", []),
            "description": t.get("description", ""),
            "detection": t.get("detection", ""),
            "data_sources": t.get("data_sources", []),
            "url": t.get("url", ""),
            "bm25_score": float(score),
        })

    return results
