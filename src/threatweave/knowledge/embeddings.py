"""Embed ATT&CK techniques and store in Qdrant for semantic retrieval.

Uses sentence-transformers (all-MiniLM-L6-v2) for local embedding and
Qdrant for vector storage (in-memory by default, with persistent option).
"""

from __future__ import annotations

import logging
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer, CrossEncoder

from threatweave.config import get_settings

logger = logging.getLogger(__name__)

# Module-level singletons (lazy-initialized)
_model: SentenceTransformer | None = None
_reranker: CrossEncoder | None = None
_client: QdrantClient | None = None


def get_embedding_model() -> SentenceTransformer:
    """Return a cached SentenceTransformer model."""
    global _model
    if _model is None:
        settings = get_settings()
        logger.info("Loading embedding model: %s", settings.embedding_model)
        _model = SentenceTransformer(settings.embedding_model)
    return _model


def get_reranker_model() -> CrossEncoder:
    """Return a cached CrossEncoder model."""
    global _reranker
    if _reranker is None:
        settings = get_settings()
        logger.info("Loading reranker model: %s", settings.reranker_model)
        _reranker = CrossEncoder(settings.reranker_model)
    return _reranker


def get_qdrant_client() -> QdrantClient:
    """Return a cached Qdrant client."""
    global _client
    if _client is None:
        settings = get_settings()
        if settings.qdrant_mode == "persistent":
            logger.info("Using persistent Qdrant at %s", settings.qdrant_path)
            _client = QdrantClient(path=settings.qdrant_path)
        else:
            logger.info("Using in-memory Qdrant.")
            _client = QdrantClient(location=":memory:")
    return _client


def reset_clients() -> None:
    """Reset cached singletons (useful for testing)."""
    global _model, _reranker, _client
    _model = None
    _reranker = None
    _client = None


def _technique_to_text(technique: dict[str, Any]) -> str:
    """Build a text representation of a technique for embedding.

    Combines name, description, tactics, platforms, and detection guidance
    into a single string for embedding.
    """
    parts = [
        f"Technique: {technique['name']} ({technique['technique_id']})",
        f"Tactics: {', '.join(technique.get('tactics', []))}",
        f"Platforms: {', '.join(technique.get('platforms', []))}",
    ]
    if technique.get("description"):
        # Truncate very long descriptions to keep embedding focused
        desc = technique["description"][:1500]
        parts.append(f"Description: {desc}")
    if technique.get("detection"):
        det = technique["detection"][:500]
        parts.append(f"Detection: {det}")
    return "\n".join(parts)


def build_index(
    techniques: list[dict[str, Any]],
    collection_name: str | None = None,
    client: QdrantClient | None = None,
) -> QdrantClient:
    """Embed techniques and store in Qdrant.

    Args:
        techniques: List of parsed ATT&CK technique documents.
        collection_name: Qdrant collection name (defaults to settings).
        client: Optional Qdrant client (for testing).

    Returns:
        The Qdrant client with the populated collection.
    """
    settings = get_settings()
    if collection_name is None:
        collection_name = settings.qdrant_collection_name
    if client is None:
        client = get_qdrant_client()

    model = get_embedding_model()

    # Build text representations
    texts = [_technique_to_text(t) for t in techniques]

    logger.info("Embedding %d techniques...", len(texts))
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
    vector_size = embeddings.shape[1]

    # Create collection (delete first if exists)
    if client.collection_exists(collection_name):
        client.delete_collection(collection_name)
    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
    )

    # Build points with technique metadata as payload
    points = [
        PointStruct(
            id=idx,
            vector=embeddings[idx].tolist(),
            payload={
                "technique_id": techniques[idx]["technique_id"],
                "name": techniques[idx]["name"],
                "tactics": techniques[idx].get("tactics", []),
                "platforms": techniques[idx].get("platforms", []),
                "description": techniques[idx].get("description", "")[:2000],
                "detection": techniques[idx].get("detection", "")[:1000],
                "data_sources": techniques[idx].get("data_sources", []),
                "url": techniques[idx].get("url", ""),
            },
        )
        for idx in range(len(techniques))
    ]

    # Upsert in batches
    batch_size = 100
    for i in range(0, len(points), batch_size):
        batch = points[i : i + batch_size]
        client.upsert(collection_name=collection_name, points=batch)
        logger.info("Upserted batch %d-%d", i, min(i + batch_size, len(points)))

    logger.info(
        "Built Qdrant index: %d points in collection '%s'.",
        len(points),
        collection_name,
    )
    return client


def search_techniques(
    query: str,
    top_k: int = 5,
    collection_name: str | None = None,
    client: QdrantClient | None = None,
    use_reranker: bool = True,
) -> list[dict[str, Any]]:
    """Semantic search for ATT&CK techniques with optional reranking.

    Args:
        query: Natural language query text.
        top_k: Number of results to return.
        collection_name: Qdrant collection name.
        client: Optional Qdrant client.
        use_reranker: Whether to use a CrossEncoder to rerank top_k * 5 results.

    Returns:
        List of technique metadata dicts with 'score' (and 'rerank_score') added.
    """
    settings = get_settings()
    if collection_name is None:
        collection_name = settings.qdrant_collection_name
    if client is None:
        client = get_qdrant_client()

    model = get_embedding_model()
    query_vector = model.encode(query).tolist()
    
    fetch_k = top_k * 5 if use_reranker else top_k

    response = client.query_points(
        collection_name=collection_name,
        query=query_vector,
        limit=fetch_k,
    )

    techniques: list[dict[str, Any]] = []
    for hit in response.points:
        payload = hit.payload or {}
        techniques.append(
            {
                "technique_id": payload.get("technique_id", ""),
                "name": payload.get("name", ""),
                "tactics": payload.get("tactics", []),
                "platforms": payload.get("platforms", []),
                "description": payload.get("description", ""),
                "detection": payload.get("detection", ""),
                "data_sources": payload.get("data_sources", []),
                "url": payload.get("url", ""),
                "score": hit.score,
            }
        )

    if use_reranker and techniques:
        reranker = get_reranker_model()
        # Rerank based on query vs (technique ID + name + description)
        pairs = [[query, f"{t['technique_id']} {t['name']} {t['description']}"] for t in techniques]
        scores = reranker.predict(pairs)
        for i, score in enumerate(scores):
            techniques[i]["rerank_score"] = float(score)
        
        # Sort by reranker score descending
        techniques.sort(key=lambda x: x["rerank_score"], reverse=True)
        techniques = techniques[:top_k]

    return techniques
