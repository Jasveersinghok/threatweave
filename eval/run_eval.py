"""ThreatWeave evaluation framework.

Runs eval dataset through the full pipeline and computes:
- Strict ATT&CK Precision, Recall, F1 (exact technique ID match)
- Tactic-level Precision, Recall (tactic family match)
- Retrieval Recall@10 (did the RAG retriever surface expected techniques?)
- Sigma validity rate (pySigma parse check)
- Hallucination rate (technique IDs not in ATT&CK)
- Avg latency per case

Usage:
    python eval/run_eval.py                # run all cases
    python eval/run_eval.py --cases 3      # run only first N cases
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Force UTF-8 so Windows cp1252 terminal doesn't crash on special chars
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

logger = logging.getLogger(__name__)

EVAL_DIR = Path(__file__).resolve().parent
DATASET_PATH = EVAL_DIR / "dataset.json"
RESULTS_DIR = EVAL_DIR / "results"


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


def compute_precision_recall_f1(
    predicted: set[str], expected: set[str]
) -> dict[str, float]:
    if not predicted and not expected:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not predicted or not expected:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    correct = predicted & expected
    precision = len(correct) / len(predicted)
    recall = len(correct) / len(expected)
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return {"precision": precision, "recall": recall, "f1": f1}


def check_sigma_validity(rules: list) -> dict:
    try:
        import yaml
    except ImportError:
        return {"total": len(rules), "valid": 0, "rate": 0.0}

    if not rules:
        return {"total": 0, "valid": 0, "rate": 0.0}

    valid = 0
    for rule in rules:
        try:
            parsed = yaml.safe_load(rule.rule_yaml)
            if isinstance(parsed, dict) and "detection" in parsed:
                valid += 1
        except Exception:
            pass

    return {
        "total": len(rules),
        "valid": valid,
        "rate": valid / len(rules) if rules else 0.0,
    }


def check_hallucination_rate(
    predicted_ids: set[str],
    all_attack_ids: set[str],
) -> dict:
    if not predicted_ids:
        return {"total": 0, "hallucinated": 0, "rate": 0.0, "hallucinated_ids": []}

    hallucinated = predicted_ids - all_attack_ids
    return {
        "total": len(predicted_ids),
        "hallucinated": len(hallucinated),
        "hallucinated_ids": sorted(hallucinated),
        "rate": len(hallucinated) / len(predicted_ids),
    }


def compute_retrieval_recall(
    expected_ids: set[str], retrieved_ids: set[str]
) -> float:
    if not expected_ids:
        return 1.0
    return len(expected_ids & retrieved_ids) / len(expected_ids)


# ---------------------------------------------------------------------------
# Load ATT&CK data
# ---------------------------------------------------------------------------


def load_attack_data() -> tuple[set[str], dict[str, set[str]]]:
    from threatweave.config import get_settings

    settings = get_settings()
    techniques_file = Path(settings.attack_techniques_file)

    if not techniques_file.exists():
        logger.warning("ATT&CK techniques file not found. Run attack_ingest first.")
        return set(), {}

    with open(techniques_file, encoding="utf-8") as f:
        techniques = json.load(f)

    all_ids: set[str] = set()
    tactic_map: dict[str, set[str]] = {}
    for t in techniques:
        tid = t["technique_id"]
        all_ids.add(tid)
        tactic_map[tid] = set(t.get("tactics", []))

    return all_ids, tactic_map


def get_retrieved_ids_for_case(query: str, bm25_queries: list[str], techniques_file: str, top_k: int = 10) -> set[str]:
    try:
        from threatweave.intelligence.tools.attack_retriever import retrieve_techniques_hybrid
        results = retrieve_techniques_hybrid(
            query=query,
            bm25_queries=bm25_queries,
            techniques_file=techniques_file,
            top_k=top_k,
        )
        return {r["technique_id"] for r in results}
    except Exception as e:
        logger.warning("Retrieval failed: %s", e)
        return set()


# ---------------------------------------------------------------------------
# Run a single eval case
# ---------------------------------------------------------------------------


async def run_single_case(
    case_data: dict,
    all_attack_ids: set[str],
    tactic_map: dict[str, set[str]],
    skip_enrichment: bool = True,
) -> dict:
    from threatweave.cases.builder import build_cases
    from threatweave.collection.normalize import normalize
    from threatweave.enrichment.pipeline import enrich_indicators
    from threatweave.intelligence.graph import run_analysis
    from threatweave.models.indicators import EnrichedIndicator, RawIndicator

    case_id = case_data["id"]
    case_name = case_data["name"]
    expected = set(case_data["expected_techniques"])

    start_time = time.time()

    # Normalize
    normalized = normalize(case_data["input_iocs"], source="eval")
    raw_indicators = [
        RawIndicator(
            ioc_id=d["ioc_id"],
            ioc_type=d["ioc_type"],
            value=d["value"],
            source=d["source"],
            source_context=d["source_context"],
        )
        for d in normalized
    ]

    # Enrich (or skip)
    if skip_enrichment:
        enriched = [
            EnrichedIndicator(indicator=ind, enrichment={}, enrichment_status="ok")
            for ind in raw_indicators
        ]
    else:
        enriched = await enrich_indicators(raw_indicators)

    # Build case
    cases = build_cases(enriched)
    if not cases:
        return {
            "case_id": case_id, "name": case_name,
            "status": "error", "error": "No cases built",
        }

    from threatweave.config import get_settings
    from threatweave.intelligence.agents.analyst import _expand_rag_query, _extract_bm25_queries
    
    settings = get_settings()
    
    # Retrieval Recall@10 — use the same Hybrid BM25 + Dense GraphRAG as the pipeline
    expanded_query = _expand_rag_query(cases[0], settings)
    bm25_queries = _extract_bm25_queries(cases[0], settings)
    retrieved_ids = get_retrieved_ids_for_case(
        query=expanded_query,
        bm25_queries=bm25_queries,
        techniques_file=str(settings.attack_techniques_file),
        top_k=50,
    )
    retrieval_recall_10 = compute_retrieval_recall(expected, retrieved_ids)

    # Run pipeline
    result = await run_analysis(cases[0])
    elapsed = time.time() - start_time

    report = result.get("report")
    analyst_output = result.get("analyst_output")

    if report is None:
        return {
            "case_id": case_id, "name": case_name,
            "status": "error", "error": "No report generated",
            "errors": result.get("errors", []),
            "elapsed_seconds": round(elapsed, 2),
        }

    # Predicted techniques from final report
    predicted = {m.technique_id for m in report.technique_table}

    # Strict precision / recall / F1
    prf_strict = compute_precision_recall_f1(predicted, expected)

    # Tactic-level
    predicted_tactics: set[str] = set()
    for pid in predicted:
        predicted_tactics.update(tactic_map.get(pid, set()))
    for m in report.technique_table:
        if m.tactic:
            predicted_tactics.add(m.tactic.lower().strip())

    expected_tactics: set[str] = set()
    for eid in expected:
        expected_tactics.update(tactic_map.get(eid, set()))

    prf_tactic = compute_precision_recall_f1(predicted_tactics, expected_tactics)

    # Sigma + hallucination
    sigma = check_sigma_validity(report.detection_rules)
    hallucination = check_hallucination_rate(predicted, all_attack_ids)

    return {
        "case_id": case_id,
        "name": case_name,
        "source": case_data.get("source", ""),
        "status": "success",
        "elapsed_seconds": round(elapsed, 2),
        "indicators_count": len(raw_indicators),
        "expected_techniques": sorted(expected),
        "predicted_techniques": sorted(predicted),
        "correct_techniques": sorted(predicted & expected),
        "missed_techniques": sorted(expected - predicted),
        "extra_techniques": sorted(predicted - expected),
        "strict_precision": round(prf_strict["precision"], 4),
        "strict_recall": round(prf_strict["recall"], 4),
        "strict_f1": round(prf_strict["f1"], 4),
        "tactic_precision": round(prf_tactic["precision"], 4),
        "tactic_recall": round(prf_tactic["recall"], 4),
        "tactic_f1": round(prf_tactic["f1"], 4),
        "retrieval_recall_10": round(retrieval_recall_10, 4),
        "retrieved_ids": sorted(retrieved_ids),
        "sigma_rules_total": sigma["total"],
        "sigma_rules_valid": sigma["valid"],
        "sigma_validity_rate": round(sigma["rate"], 4),
        "hallucination_rate": round(hallucination["rate"], 4),
        "hallucinated_ids": hallucination.get("hallucinated_ids", []),
        "validation_status": report.validation_status,
        "pipeline_errors": result.get("errors", []),
    }


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


async def run_eval(
    max_cases: int | None = None,
    skip_enrichment: bool = True,
) -> None:
    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    if max_cases:
        dataset = dataset[:max_cases]

    total = len(dataset)

    all_attack_ids, tactic_map = load_attack_data()
    logger.info("Loaded %d ATT&CK technique IDs", len(all_attack_ids))

    print("\n" + "=" * 65)
    print("  ThreatWeave Evaluation  ---  " + str(total) + " case(s)")
    print("=" * 65 + "\n")

    results: list[dict] = []

    for i, case_data in enumerate(dataset):
        sep = "-" * 65
        print(sep)
        print(f"[{i+1}/{total}] {case_data['id']}: {case_data['name']}")
        print(f"  Source  : {case_data.get('source', 'N/A')}")
        print(f"  IOCs    : {len(case_data['input_iocs'])}")
        print(f"  Expected: {', '.join(case_data['expected_techniques'])}")
        print("  Running pipeline...")

        try:
            result = await run_single_case(
                case_data, all_attack_ids, tactic_map, skip_enrichment
            )
            results.append(result)

            if result["status"] == "success":
                sp   = result["strict_precision"]
                sr   = result["strict_recall"]
                sf1  = result["strict_f1"]
                tp   = result["tactic_precision"]
                tr_  = result["tactic_recall"]
                rr10 = result["retrieval_recall_10"]
                sv   = result["sigma_validity_rate"]
                hr   = result["hallucination_rate"]
                t    = result["elapsed_seconds"]

                print(f"  DONE in {t:.1f}s  |  Validation: {result['validation_status'].upper()}")
                print()
                print(f"  Predicted : {', '.join(result['predicted_techniques']) or '(none)'}")
                print(f"  Correct   : {', '.join(result['correct_techniques']) or '(none)'}")
                print(f"  Missed    : {', '.join(result['missed_techniques']) or '(none)'}")
                print(f"  Extra     : {', '.join(result['extra_techniques']) or '(none)'}")
                print()
                print("  --- METRICS ---")
                print(f"  Strict  Precision  : {sp:.2%}")
                print(f"  Strict  Recall     : {sr:.2%}")
                print(f"  Strict  F1         : {sf1:.2%}")
                print(f"  Tactic  Precision  : {tp:.2%}")
                print(f"  Tactic  Recall     : {tr_:.2%}")
                print(f"  Retrieval Rec@10   : {rr10:.2%}")
                print(f"  Sigma Validity     : {result['sigma_rules_valid']}/{result['sigma_rules_total']} rules ({sv:.0%})")
                print(f"  Hallucination      : {hr:.0%}  {result['hallucinated_ids'] or ''}")
                if result.get("pipeline_errors"):
                    print(f"  Warnings: {'; '.join(result['pipeline_errors'][:2])}")
            else:
                print(f"  ERROR: {result.get('error', 'Unknown')}")
                for err in result.get("errors", [])[:3]:
                    print(f"    -> {err}")

        except Exception as e:
            logger.exception("Case %s raised an exception", case_data["id"])
            results.append({
                "case_id": case_data["id"],
                "name": case_data["name"],
                "status": "error",
                "error": str(e),
            })
            print(f"  EXCEPTION: {e}")

        print()

    # Aggregate
    successful = [r for r in results if r["status"] == "success"]
    n = len(successful)

    if n:
        def avg(key: str) -> float:
            return sum(r[key] for r in successful) / n

        agg = {
            "avg_strict_precision":    round(avg("strict_precision"), 4),
            "avg_strict_recall":       round(avg("strict_recall"), 4),
            "avg_strict_f1":           round(avg("strict_f1"), 4),
            "avg_tactic_precision":    round(avg("tactic_precision"), 4),
            "avg_tactic_recall":       round(avg("tactic_recall"), 4),
            "avg_retrieval_recall_10": round(avg("retrieval_recall_10"), 4),
            "avg_sigma_validity":      round(avg("sigma_validity_rate"), 4),
            "avg_hallucination":       round(avg("hallucination_rate"), 4),
            "avg_latency_seconds":     round(avg("elapsed_seconds"), 2),
        }
    else:
        agg = {k: 0.0 for k in [
            "avg_strict_precision", "avg_strict_recall", "avg_strict_f1",
            "avg_tactic_precision", "avg_tactic_recall",
            "avg_retrieval_recall_10", "avg_sigma_validity",
            "avg_hallucination", "avg_latency_seconds",
        ]}

    summary = {
        "run_timestamp": datetime.now(UTC).isoformat(),
        "total_cases": len(dataset),
        "successful_cases": n,
        "failed_cases": len(results) - n,
        **agg,
    }

    # Save
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    results_path = RESULTS_DIR / f"eval_{timestamp}.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "cases": results}, f, indent=2, default=str)

    # Print summary
    W = 65
    print("=" * W)
    print("  EVALUATION SUMMARY  (numbers for your resume)")
    print("=" * W)
    print(f"  Cases               : {n}/{len(dataset)} successful")
    print()
    print(f"  Strict  Precision   : {agg['avg_strict_precision']:.2%}")
    print(f"  Strict  Recall      : {agg['avg_strict_recall']:.2%}")
    print(f"  Strict  F1          : {agg['avg_strict_f1']:.2%}")
    print()
    print(f"  Tactic  Precision   : {agg['avg_tactic_precision']:.2%}")
    print(f"  Tactic  Recall      : {agg['avg_tactic_recall']:.2%}")
    print()
    print(f"  Retrieval Recall@10 : {agg['avg_retrieval_recall_10']:.2%}")
    print()
    print(f"  Sigma Validity      : {agg['avg_sigma_validity']:.0%}")
    print(f"  Hallucination Rate  : {agg['avg_hallucination']:.0%}")
    print()
    print(f"  Avg Latency / Case  : {agg['avg_latency_seconds']:.1f}s")
    print("=" * W)
    print(f"\n  Full results: {results_path}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatWeave Evaluation Framework"
    )
    parser.add_argument(
        "--cases", type=int, default=None,
        help="Max number of eval cases to run (default: all)",
    )
    parser.add_argument(
        "--skip-enrichment", action="store_true", default=False,
        help="Skip live enrichment (faster, default: False)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose logging",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    asyncio.run(run_eval(args.cases, args.skip_enrichment))


if __name__ == "__main__":
    main()
