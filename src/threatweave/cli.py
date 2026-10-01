"""ThreatWeave CLI — end-to-end analysis pipeline.

Usage:
    python -m threatweave.cli analyze <file_path>
    python -m threatweave.cli analyze data/samples/sample_case_apt29.json
    python -m threatweave.cli collect --source otx
    python -m threatweave.cli ingest-attack

Pipeline:
    Load → Normalize → Enrich → Build Cases → Run Agents → Export
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


async def analyze(file_path: str, skip_enrichment: bool = False) -> None:
    """Run the full analysis pipeline on an indicator file.

    Args:
        file_path: Path to JSON or CSV indicator file.
        skip_enrichment: Skip enrichment step (for testing without APIs).
    """
    from threatweave.cases.builder import build_cases
    from threatweave.collection.file_loader import load_indicators
    from threatweave.enrichment.pipeline import enrich_indicators
    from threatweave.export.json_report import export_json
    from threatweave.intelligence.graph import run_analysis
    from threatweave.models.indicators import EnrichedIndicator

    # Step 1: Load and normalize
    print(f"\n📥 Loading indicators from {file_path}...")
    indicators = load_indicators(file_path)
    print(f"   Loaded {len(indicators)} normalized indicators")

    # Step 2: Enrich
    if skip_enrichment:
        print("⏭️  Skipping enrichment (--skip-enrichment)")
        enriched = [
            EnrichedIndicator(
                indicator=ind, enrichment={}, enrichment_status="ok"
            )
            for ind in indicators
        ]
    else:
        print("\n🔍 Enriching indicators...")
        enriched = await enrich_indicators(indicators)
        ok = sum(1 for e in enriched if e.enrichment_status == "ok")
        partial = sum(1 for e in enriched if e.enrichment_status == "partial")
        failed = sum(1 for e in enriched if e.enrichment_status == "failed")
        print(f"   Enrichment: {ok} ok, {partial} partial, {failed} failed")

    # Step 3: Build cases
    print("\n📦 Building cases...")
    cases = build_cases(enriched)
    print(f"   Built {len(cases)} case(s)")

    # Step 4: Run agent pipeline on each case
    for i, case in enumerate(cases, 1):
        print(
            f"\n🤖 Running agent pipeline on case {i}/{len(cases)}: "
            f"{case.case_id}"
        )
        print(f"   Indicators: {len(case.indicators)}")
        print(f"   Reason: {case.grouping_reason}")

        result = await run_analysis(case)

        report = result.get("report")
        if report is not None:
            # Export JSON
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            json_path = output_dir / f"{case.case_id}_report.json"
            export_json(report, str(json_path))

            print(f"\n✅ Report: {report.title}")
            print(f"   📊 Techniques: {len(report.technique_table)}")
            print(f"   🛡️  Detection Rules: {len(report.detection_rules)}")
            print(
                f"   ✔️  Validation: {report.validation_status}"
            )
            print(f"   💾 Saved to: {json_path}")

            # Try STIX export
            try:
                from threatweave.export.stix_builder import (
                    build_stix_bundle,
                )

                bundle = build_stix_bundle(case, report)
                stix_path = output_dir / f"{case.case_id}_stix.json"
                with open(stix_path, "w", encoding="utf-8") as f:
                    json.dump(bundle, f, indent=2, default=str)
                print(f"   📋 STIX bundle: {stix_path}")
            except Exception as e:
                print(f"   ⚠️  STIX export failed: {e}")

            print("\n   📋 Recommended Actions:")
            for action in report.recommended_actions[:5]:
                print(f"      → {action}")
        else:
            print("\n❌ No report generated")
            for err in result.get("errors", []):
                print(f"   Error: {err}")


async def collect_otx() -> None:
    """Pull indicators from OTX and analyze them."""
    from threatweave.collection.otx_collector import collect_from_otx

    print("\n📡 Collecting indicators from AlienVault OTX...")
    indicators = collect_from_otx()

    if not indicators:
        print("   No indicators collected (check OTX_API_KEY in .env)")
        return

    print(f"   Collected {len(indicators)} indicators")

    # Save to temp file and analyze
    import tempfile

    data = [
        {
            "type": ind.ioc_type,
            "value": ind.value,
            "source": ind.source,
            "context": ind.source_context,
        }
        for ind in indicators
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(data, f)
        tmp_path = f.name

    await analyze(tmp_path, skip_enrichment=False)


def ingest_attack() -> None:
    """Download and embed ATT&CK data into vector store."""
    from threatweave.knowledge.attack_ingest import main as ingest_main

    print("\n📚 Ingesting MITRE ATT&CK data...")
    ingest_main()
    print("   ✅ ATT&CK knowledge base ready")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="threatweave",
        description="ThreatWeave — Multi-Agent CTI Analysis",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run full analysis pipeline on an indicator file",
    )
    analyze_parser.add_argument(
        "file", help="Path to JSON or CSV indicator file"
    )
    analyze_parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip enrichment step",
    )
    analyze_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose logging"
    )

    # collect command
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect indicators from external sources",
    )
    collect_parser.add_argument(
        "--source",
        choices=["otx"],
        default="otx",
        help="Source to collect from (default: otx)",
    )
    collect_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose logging"
    )

    # ingest-attack command
    subparsers.add_parser(
        "ingest-attack",
        help="Download and embed MITRE ATT&CK data",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    log_level = (
        logging.DEBUG
        if hasattr(args, "verbose") and args.verbose
        else logging.INFO
    )
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "analyze":
        asyncio.run(analyze(args.file, args.skip_enrichment))
    elif args.command == "collect":
        asyncio.run(collect_otx())
    elif args.command == "ingest-attack":
        ingest_attack()


if __name__ == "__main__":
    main()
