"""Analyst agent — maps case indicators to ATT&CK techniques using RAG.

Retrieves relevant ATT&CK techniques via semantic search, builds context
from case indicators + enrichment + retrieved techniques, calls LLM via
instructor for structured output, and returns AnalystOutput.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import instructor
import litellm

from threatweave.config import get_settings
from threatweave.intelligence.tools.attack_retriever import retrieve_techniques
from threatweave.models.agent_state import AnalystOutput
from threatweave.models.case import Case

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "analyst.md"


def _load_system_prompt() -> str:
    """Load the analyst system prompt from markdown file."""
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _build_case_context(case: Case) -> str:
    """Build a structured context string from case indicators and enrichment."""
    lines: list[str] = [f"## Case: {case.case_id}", f"Grouping reason: {case.grouping_reason}", ""]
    lines.append("## Indicators")
    for ei in case.indicators:
        ind = ei.indicator
        lines.append(f"- **{ind.ioc_type}**: `{ind.value}` (source: {ind.source})")
        if ind.source_context:
            lines.append(f"  Context: {ind.source_context}")
        if ei.enrichment:
            lines.append(f"  Enrichment: {json.dumps(ei.enrichment, default=str)}")
        if ei.errors:
            lines.append(f"  Enrichment errors: {json.dumps(ei.errors)}")
    return "\n".join(lines)


def _build_technique_context(techniques: list[dict[str, Any]]) -> str:
    """Build a structured context string from retrieved ATT&CK techniques."""
    lines: list[str] = ["## Retrieved ATT&CK Technique Candidates", ""]
    lines.append(
        "You MUST select ONLY from these candidates. Do NOT invent technique IDs."
    )
    lines.append("")
    for i, t in enumerate(techniques, 1):
        lines.append(f"### Candidate {i}: {t['technique_id']} — {t['name']}")
        lines.append(f"- Tactics: {', '.join(t.get('tactics', []))}")
        lines.append(f"- Platforms: {', '.join(t.get('platforms', []))}")
        desc = t.get("description", "")[:300]
        if desc:
            lines.append(f"- Description: {desc}...")
        lines.append("")
    return "\n".join(lines)


# Key ATT&CK tactic areas to ensure coverage across the kill chain
_TACTIC_PROBES = [
    ("initial-access", "How did the adversary gain initial access to the target environment?"),
    ("execution",      "What code execution methods did the adversary use after gaining access?"),
    ("persistence",    "How did the adversary maintain persistence on the compromised system?"),
    ("defense-evasion","What obfuscation or defense evasion techniques were used?"),
    ("command-and-control", "How did the adversary communicate back to their C2 infrastructure?"),
    ("collection",    "What data or credentials did the adversary collect from the victim?"),
]


def _expand_rag_query(case: Case, settings: Any) -> str:
    """Use the LLM to expand raw IOCs into a behavioral description for better RAG."""
    query_parts: list[str] = []
    for ei in case.indicators:
        ind = ei.indicator
        query_parts.append(f"{ind.ioc_type}: {ind.value}")
        if ind.source_context:
            query_parts.append(f"Context: {ind.source_context}")
        if ei.enrichment:
            for provider, data in ei.enrichment.items():
                if isinstance(data, dict) and data.get("found"):
                    if data.get("pulses"):
                        query_parts.append(f"OTX pulses: {', '.join(data['pulses'][:3])}")
                    if data.get("tags"):
                        query_parts.append(f"OTX tags: {', '.join(data['tags'][:5])}")
                    if data.get("description"):
                        query_parts.append(f"CVE description: {data['description'][:200]}")
    
    raw_text = " | ".join(query_parts)
    
    prompt = (
        "You are an expert cyber threat intelligence analyst specializing in MITRE ATT&CK. "
        "Given these IOCs and context, write a concise 2-sentence behavioral description of the adversary's "
        "overall attack campaign using MITRE ATT&CK terminology. "
        "Focus on adversary goals and behaviors, NOT on specific file hashes, IPs, or domain names.\n\n"
        f"IOCs: {raw_text}\n\n"
        "Behavioral description (2 sentences, ATT&CK terminology only):"
    )

    try:
        response = litellm.completion(
            model=settings.llm_fallback_model or settings.llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=120,
        )
        expanded = response.choices[0].message.content.strip()
        logger.info("Query expansion generated: %s", expanded)
        return expanded
    except Exception as e:
        logger.warning("Query expansion failed: %s", e)
        return raw_text


def _extract_bm25_queries(case: Case, settings: Any | None = None) -> list[str]:
    """Use LLM to convert IOC context into precise ATT&CK vocabulary for BM25 keyword search.
    
    BM25 finds techniques perfectly when given exact ATT&CK terms.
    This function generates those terms by asking the LLM to identify the
    specific ATT&CK technique NAMES implied by each IOC context.
    """
    if settings is None:
        settings = get_settings()
    
    # Build a flat list of all context strings available
    all_contexts = []
    for ei in case.indicators:
        ind = ei.indicator
        if ind.source_context:
            all_contexts.append(f"- {ind.ioc_type}: {ind.source_context}")
        if ei.enrichment:
            for provider, data in ei.enrichment.items():
                if isinstance(data, dict):
                    if data.get("description"):
                        all_contexts.append(f"- CVE desc: {data['description'][:150]}")
                    if data.get("pulses"):
                        all_contexts.append(f"- OTX pulses: {', '.join(data['pulses'][:3])}")
                    if data.get("tags"):
                        all_contexts.append(f"- OTX tags: {', '.join(data['tags'][:5])}")
    
    context_text = "\n".join(all_contexts)
    
    prompt = (
        "You are an expert Threat Intelligence Analyst. Your task is to map the provided indicators to EXACT MITRE ATT&CK technique names.\n\n"
        "INSTRUCTIONS:\n"
        "1. Read the indicators and their context. Identify the Threat Actor or Campaign (e.g., APT29, SolarWinds, SUNBURST).\n"
        "2. Recall the KNOWN PLAYBOOK of that specific actor/campaign from your internal knowledge.\n"
        "3. Output EXACTLY 20 MITRE ATT&CK technique names that this actor is known to use.\n"
        "4. Output ONLY the raw technique names. Do NOT include technique IDs. Do NOT include extra words (like 'usage', 'communication'). Do NOT include conversational text.\n"
        "5. Example valid outputs: 'powershell', 'process hollowing', 'steganography', 'obfuscated files', 'web protocols', 'supply chain compromise', 'scheduled task', 'process discovery', 'dll side-loading', 'valid accounts'.\n\n"
        f"Indicators:\n{context_text}\n\n"
        "20 ATT&CK technique names (one per line):"
    )
    
    try:
        response = litellm.completion(
            model=settings.llm_fallback_model or settings.llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=200,
        )
        output = response.choices[0].message.content.strip()
        # Parse the lines, strip numbering/bullets
        lines = [
            line.strip().lstrip("0123456789.-) ").strip()
            for line in output.splitlines()
            if line.strip() and len(line.strip()) > 3
        ]
        logger.info("BM25 keyword phrases: %s", lines)
        queries = lines[:20] if lines else []
        for ei in case.indicators:
            if ei.indicator.source_context:
                queries.append(ei.indicator.source_context)
        return queries
    except Exception as e:
        logger.warning("BM25 query generation failed: %s", e)
        # Fallback: use context strings directly
        return [ei.indicator.source_context for ei in case.indicators if ei.indicator.source_context]


def run_analyst(case: Case) -> AnalystOutput:
    """Run the Analyst agent on a case.

    1. Builds a summary query from case indicators
    2. Retrieves top-10 ATT&CK techniques via semantic search
    3. Calls LLM with case context + technique candidates
    4. Returns structured AnalystOutput

    Args:
        case: The case to analyze.

    Returns:
        AnalystOutput with threat assessment and technique mappings.
    """
    settings = get_settings()

    # Step 1: Generate behavioral summary query for dense vector search
    logger.info("Expanding RAG query for case %s", case.case_id)
    expanded_query = _expand_rag_query(case, settings)

    # Step 2: Extract BM25 keyword queries directly from context strings
    bm25_queries = _extract_bm25_queries(case, settings)
    logger.info("Extracted %d BM25 keyword queries", len(bm25_queries))

    # Step 3: Hybrid Retrieval = BM25 + Dense GraphRAG + Cross-Encoder reranking
    logger.info("Running Hybrid BM25 + Dense GraphRAG retrieval")
    from threatweave.intelligence.tools.attack_retriever import retrieve_techniques_hybrid
    techniques = retrieve_techniques_hybrid(
        query=expanded_query,
        bm25_queries=bm25_queries,
        techniques_file=str(settings.attack_techniques_file),
        top_k=50,
    )
    logger.info("Retrieved %d technique candidates (hybrid)", len(techniques))

    # Build prompts
    system_prompt = _load_system_prompt()
    case_context = _build_case_context(case)
    technique_context = _build_technique_context(techniques)
    user_message = f"{case_context}\n\n{technique_context}"

    # Call LLM via instructor for structured output
    logger.info("Calling LLM for Analyst agent (model: %s)", settings.llm_model)
    client = instructor.from_litellm(litellm.completion, mode=instructor.Mode.JSON)

    try:
        result = client.chat.completions.create(
            model=settings.llm_model,
            response_model=AnalystOutput,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_retries=2,
            temperature=0.2,

        )
    except Exception:
        logger.exception("Analyst agent LLM call failed")
        raise

    logger.info(
        "Analyst produced %d technique mappings", len(result.technique_mappings)
    )
    return result
