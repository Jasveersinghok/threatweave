"""ATT&CK semantic retrieval tool.

Takes a natural language query, embeds it, and performs cosine similarity
search in Qdrant to return the top-k ATT&CK techniques with full metadata.
"""

from __future__ import annotations

from typing import Any

from threatweave.knowledge.embeddings import search_techniques


def retrieve_techniques(query: str, top_k: int = 10) -> list[dict[str, Any]]:
    """Retrieve top-k ATT&CK techniques matching a query via semantic search.

    Args:
        query: Natural language description of the threat behavior.
        top_k: Number of techniques to return (default: 5).

    Returns:
        List of technique dicts with: technique_id, name, tactics,
        platforms, description, detection, data_sources, url, score.
    """
    return search_techniques(query=query, top_k=top_k)


def retrieve_techniques_multi(queries: list[str], top_k: int = 10) -> list[dict[str, Any]]:
    """Retrieve techniques using multiple search queries, deduplicate, and rerank.
    
    Args:
        queries: List of distinct search queries.
        top_k: Number of final techniques to return.
        
    Returns:
        List of technique metadata dictionaries.
    """
    from threatweave.knowledge.embeddings import get_reranker_model
    
    all_techniques = {}
    for q in queries:
        res = search_techniques(query=q, top_k=15, use_reranker=False)
        for t in res:
            all_techniques[t["technique_id"]] = t
            
    unique_techs = list(all_techniques.values())
    if not unique_techs:
        return []
        
    reranker = get_reranker_model()
    combined_query = " ".join(queries)
    pairs = [[combined_query, f"{t['technique_id']} {t['name']} {t['description']}"] for t in unique_techs]
    scores = reranker.predict(pairs)
    for i, score in enumerate(scores):
        unique_techs[i]["rerank_score"] = float(score)
        
    unique_techs.sort(key=lambda x: x["rerank_score"], reverse=True)
    return unique_techs[:top_k]


def retrieve_techniques_graphrag(query: str, top_k: int = 10) -> list[dict[str, Any]]:
    """GraphRAG: Use vector search to find entry nodes, then traverse parent/child graph edges.
    
    1. Vector search finds Top-5 semantic 'entry points'.
    2. We expand the graph by fetching the parent of each entry point, and ALL sub-techniques.
    3. We run the Cross-Encoder over the entire expanded graph neighborhood to pick the true Top-10.
    """
    import json
    from threatweave.config import get_settings
    from threatweave.knowledge.embeddings import search_techniques, get_reranker_model

    settings = get_settings()
    with open(settings.attack_techniques_file, "r", encoding="utf-8") as f:
        all_techniques_raw = json.load(f)
        
    tech_lookup = {t["technique_id"]: t for t in all_techniques_raw}

    # Step 1: Semantic entry points (flat RAG)
    entry_nodes = search_techniques(query=query, top_k=5, use_reranker=False)
    
    # Step 2: Graph Traversal (expand to parents and children)
    expanded_ids = set()
    for node in entry_nodes:
        tid = node["technique_id"]
        expanded_ids.add(tid)
        # Find parent ID
        parent_id = tid.split('.')[0]
        expanded_ids.add(parent_id)
        # Find all children of the parent (siblings or direct children)
        for cand_id in tech_lookup.keys():
            if cand_id.startswith(parent_id + "."):
                expanded_ids.add(cand_id)
                
    # Gather full nodes for the expanded neighborhood
    neighborhood = []
    for eid in expanded_ids:
        if eid in tech_lookup:
            neighborhood.append(tech_lookup[eid])
            
    if not neighborhood:
        return []

    # Step 3: Cross-Encoder Reranking of the Graph Neighborhood
    reranker = get_reranker_model()
    pairs = [[query, f"{t['technique_id']} {t['name']} {t.get('description', '')}"] for t in neighborhood]
    scores = reranker.predict(pairs)
    
    for i, score in enumerate(scores):
        neighborhood[i]["rerank_score"] = float(score)
        
    neighborhood.sort(key=lambda x: x["rerank_score"], reverse=True)
    
    # Return formatted like Qdrant payload
    final = []
    for t in neighborhood[:top_k]:
        final.append({
            "technique_id": t.get("technique_id", ""),
            "name": t.get("name", ""),
            "tactics": t.get("tactics", []),
            "platforms": t.get("platforms", []),
            "description": t.get("description", ""),
            "detection": t.get("detection", ""),
            "data_sources": t.get("data_sources", []),
            "url": t.get("url", ""),
            "score": t.get("rerank_score", 0.0),
            "rerank_score": t.get("rerank_score", 0.0)
        })
        
    return final


def retrieve_techniques_multi_graphrag(queries: list[str], top_k: int = 10) -> list[dict[str, Any]]:
    """Multi-Vector GraphRAG: one graph traversal per query, merge all neighborhoods, rerank.
    
    Each query targets a different ATT&CK tactic (initial-access, execution, persistence, etc.)
    ensuring the final Top-K has diverse kill-chain coverage instead of getting dominated
    by a single semantic cluster.
    
    Args:
        queries: List of tactic-specific behavioral query strings.
        top_k: Number of final techniques to return.
    """
    import json
    from threatweave.config import get_settings
    from threatweave.knowledge.embeddings import search_techniques, get_reranker_model

    settings = get_settings()
    with open(settings.attack_techniques_file, "r", encoding="utf-8") as f:
        all_techniques_raw = json.load(f)
        
    tech_lookup = {t["technique_id"]: t for t in all_techniques_raw}

    # Step 1: For each tactic query, run semantic search + graph expansion
    merged_neighborhood: dict[str, dict] = {}
    
    for query in queries:
        # Semantic entry points for this tactic
        entry_nodes = search_techniques(query=query, top_k=3, use_reranker=False)
        
        # Graph expand each entry node
        for node in entry_nodes:
            tid = node["technique_id"]
            parent_id = tid.split('.')[0]
            
            # Add the entry node, its parent, and ALL siblings/children
            for cand_id, cand_tech in tech_lookup.items():
                if (
                    cand_id == tid or
                    cand_id == parent_id or
                    cand_id.startswith(parent_id + ".")
                ):
                    merged_neighborhood[cand_id] = cand_tech

    neighborhood = list(merged_neighborhood.values())
    if not neighborhood:
        return []

    # Step 2: Cross-Encoder reranking over the entire merged neighborhood
    # Use a combined query string for the reranker
    combined_query = " ".join(queries)
    reranker = get_reranker_model()
    pairs = [[combined_query, f"{t['technique_id']} {t['name']} {t.get('description', '')[:300]}"] for t in neighborhood]
    scores = reranker.predict(pairs)
    
    for i, score in enumerate(scores):
        neighborhood[i]["rerank_score"] = float(score)
        
    neighborhood.sort(key=lambda x: x["rerank_score"], reverse=True)
    
    # Return top_k formatted results
    final = []
    for t in neighborhood[:top_k]:
        final.append({
            "technique_id": t.get("technique_id", ""),
            "name": t.get("name", ""),
            "tactics": t.get("tactics", []),
            "platforms": t.get("platforms", []),
            "description": t.get("description", ""),
            "detection": t.get("detection", ""),
            "data_sources": t.get("data_sources", []),
            "url": t.get("url", ""),
            "score": t.get("rerank_score", 0.0),
            "rerank_score": t.get("rerank_score", 0.0)
        })
        
    return final


def retrieve_techniques_hybrid(
    query: str,
    bm25_queries: list[str],
    techniques_file: str,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Hybrid RAG: BM25 keyword + Dense Vector GraphRAG + Cross-Encoder reranking.

    1. BM25 search with multiple keyword queries (finds exact ATT&CK term matches).
    2. Dense GraphRAG search with the behavioral query (finds semantic neighbors).
    3. Merge all candidates, deduplicate.
    4. Cross-Encoder reranks the merged pool.

    BM25 finds 'T1195.002' when query says 'supply chain compromise'.
    Dense GraphRAG finds 'T1071.001' from behavioral context about web C2.
    Cross-Encoder picks the best 10 from the combined pool.
    """
    import json
    from threatweave.knowledge.bm25_search import bm25_search
    from threatweave.knowledge.embeddings import search_techniques, get_reranker_model

    with open(techniques_file, "r", encoding="utf-8") as f:
        all_techniques_raw = json.load(f)
    tech_lookup = {t["technique_id"]: t for t in all_techniques_raw}

    merged: dict[str, dict] = {}
    rrf_scores: dict[str, float] = {}

    def add_to_rrf(tid: str, rank: int, tech: dict, weight: float = 1.0):
        if tid not in merged:
            merged[tid] = tech
        # Weighted RRF formula
        rrf_scores[tid] = rrf_scores.get(tid, 0.0) + (weight / (60 + rank))

    # --- BM25 leg: one search per bm25 query ---
    for bq in bm25_queries:
        bm25_results = bm25_search(bq, techniques_file, top_k=15)
        for rank, r in enumerate(bm25_results, start=1):
            tid = r["technique_id"]
            # Double weight for exact BM25 keyword matches
            add_to_rrf(tid, rank, tech_lookup.get(tid, r), weight=2.0)

    # --- Dense GraphRAG leg ---
    # use_reranker=False because we use RRF to merge instead
    entry_nodes = search_techniques(query=query, top_k=15, use_reranker=False)
    for rank, node in enumerate(entry_nodes, start=1):
        tid = node["technique_id"]
        # Standard weight for dense semantic matches
        add_to_rrf(tid, rank, tech_lookup.get(tid, node), weight=1.0)

    neighborhood = list(merged.values())
    if not neighborhood:
        return []

    # Apply RRF scores and sort
    for t in neighborhood:
        t["rerank_score"] = rrf_scores.get(t["technique_id"], 0.0)

    neighborhood.sort(key=lambda x: x["rerank_score"], reverse=True)

    return [
        {
            "technique_id": t.get("technique_id", ""),
            "name": t.get("name", ""),
            "tactics": t.get("tactics", []),
            "platforms": t.get("platforms", []),
            "description": t.get("description", ""),
            "detection": t.get("detection", ""),
            "data_sources": t.get("data_sources", []),
            "url": t.get("url", ""),
            "score": t.get("rerank_score", 0.0),
            "rerank_score": t.get("rerank_score", 0.0),
        }
        for t in neighborhood[:top_k]
    ]
