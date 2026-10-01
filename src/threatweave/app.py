"""ThreatWeave Streamlit UI — interactive CTI analysis dashboard.

Launch with: streamlit run src/threatweave/app.py
"""

from __future__ import annotations

import asyncio
import json
import time
from io import StringIO
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ThreatWeave — CTI Analysis",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(99, 102, 241, 0.3);
    }
    .main-header h1 {
        color: #e2e8f0;
        margin: 0;
        font-size: 2rem;
    }
    .main-header p {
        color: #94a3b8;
        margin: 0.25rem 0 0 0;
        font-size: 0.95rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b, #334155);
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid rgba(99, 102, 241, 0.2);
        text-align: center;
    }
    .metric-card h3 {
        color: #818cf8;
        font-size: 1.8rem;
        margin: 0;
    }
    .metric-card p {
        color: #94a3b8;
        font-size: 0.85rem;
        margin: 0.25rem 0 0 0;
    }
    .technique-badge {
        display: inline-block;
        background: rgba(99, 102, 241, 0.2);
        color: #a5b4fc;
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        margin: 0.15rem;
        border: 1px solid rgba(99, 102, 241, 0.3);
    }
    .stix-info {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 8px;
        padding: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="main-header">
        <h1>🕸️ ThreatWeave</h1>
        <p>Multi-Agent Cyber Threat Intelligence Analysis System</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Session state init
# ---------------------------------------------------------------------------
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "case" not in st.session_state:
    st.session_state.case = None
if "enriched_indicators" not in st.session_state:
    st.session_state.enriched_indicators = None
if "processing_time" not in st.session_state:
    st.session_state.processing_time = 0.0


# ---------------------------------------------------------------------------
# Helper: run async in streamlit
# ---------------------------------------------------------------------------
def _run_async(coro):
    """Run an async coroutine in Streamlit's sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------
def run_pipeline(
    indicators_data: list[dict],
    skip_enrichment: bool = True,
) -> None:
    """Execute the full ThreatWeave pipeline with progress display."""
    from threatweave.cases.builder import build_cases
    from threatweave.collection.normalize import normalize
    from threatweave.enrichment.pipeline import enrich_indicators
    from threatweave.intelligence.graph import run_analysis
    from threatweave.models.indicators import (
        EnrichedIndicator,
        RawIndicator,
    )

    start_time = time.time()

    with st.status("🔄 Running ThreatWeave Pipeline...", expanded=True) as status:
        # Step 1: Normalize
        st.write("📥 **Normalizing indicators...**")
        normalized = normalize(indicators_data, source="manual")

        raw_indicators = [
            RawIndicator(
                ioc_id=d["ioc_id"],
                ioc_type=d["ioc_type"],  # type: ignore[arg-type]
                value=d["value"],
                source=d["source"],
                source_context=d["source_context"],
            )
            for d in normalized
        ]
        st.write(f"   ✅ {len(raw_indicators)} valid indicators")

        if not raw_indicators:
            status.update(
                label="❌ No valid indicators found",
                state="error",
            )
            return

        # Step 2: Enrich
        if skip_enrichment:
            st.write("⏭️ **Skipping enrichment** (no API keys)")
            enriched = [
                EnrichedIndicator(
                    indicator=ind,
                    enrichment={},
                    enrichment_status="ok",
                )
                for ind in raw_indicators
            ]
        else:
            st.write("🔍 **Enriching indicators...**")
            enriched = _run_async(enrich_indicators(raw_indicators))
            ok = sum(1 for e in enriched if e.enrichment_status == "ok")
            partial = sum(
                1 for e in enriched if e.enrichment_status == "partial"
            )
            failed = sum(
                1 for e in enriched if e.enrichment_status == "failed"
            )
            st.write(f"   ✅ {ok} ok, {partial} partial, {failed} failed")

        st.session_state.enriched_indicators = enriched

        # Step 3: Build cases
        st.write("📦 **Building cases...**")
        cases = build_cases(enriched)
        st.write(f"   ✅ {len(cases)} case(s) created")

        # Step 4: Run agent pipeline
        for i, case in enumerate(cases):
            st.write(
                f"🤖 **Running agents on case {i + 1}/{len(cases)}...**"
            )
            st.session_state.case = case

            # Agent progress
            st.write("   🧠 Analyst: Mapping ATT&CK techniques...")
            st.write("   🎯 Hunter: Generating Sigma rules...")
            st.write("   🔴 Red Team: Adversarial critique...")
            st.write("   ✔️ Validator: Quality checks...")
            st.write("   📝 Reporter: Building final report...")

            result = _run_async(run_analysis(case))
            st.session_state.analysis_result = result

            report = result.get("report")
            if report:
                st.write(f"   ✅ Report generated: {report.title}")
            else:
                errors = result.get("errors", [])
                for err in errors:
                    st.write(f"   ❌ Error: {err}")

        elapsed = time.time() - start_time
        st.session_state.processing_time = elapsed
        status.update(
            label=f"✅ Analysis complete ({elapsed:.1f}s)",
            state="complete",
        )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 📂 Input")

    # File upload
    uploaded_file = st.file_uploader(
        "Upload IOC file",
        type=["json", "csv"],
        help="JSON array or CSV with columns: type, value, source, context",
    )

    # Manual entry
    st.markdown("---")
    st.markdown("### ✏️ Manual IOC Entry")
    manual_iocs = st.text_area(
        "Enter IOCs (one per line, format: type,value,context)",
        height=120,
        placeholder="ipv4,198.51.100.42,C2 server\ndomain,evil.com,Phishing",
    )

    st.markdown("---")
    skip_enrich = st.checkbox("Skip enrichment", value=True)

    analyze_btn = st.button("🚀 Analyze", use_container_width=True, type="primary")

    # Handle analyze button
    if analyze_btn:
        indicators_data: list[dict] = []

        if uploaded_file is not None:
            ext = Path(uploaded_file.name).suffix.lower()
            content = uploaded_file.read().decode("utf-8")

            if ext == ".json":
                indicators_data = json.loads(content)
            elif ext == ".csv":
                import csv

                reader = csv.DictReader(StringIO(content))
                for row in reader:
                    indicators_data.append(
                        {
                            "type": row.get("type", ""),
                            "value": row.get("value", ""),
                            "source": row.get("source", "file"),
                            "context": row.get("context", ""),
                        }
                    )

        if manual_iocs.strip():
            for line in manual_iocs.strip().split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2:
                    indicators_data.append(
                        {
                            "type": parts[0],
                            "value": parts[1],
                            "source": "manual",
                            "context": parts[2] if len(parts) > 2 else "",
                        }
                    )

        if not indicators_data:
            st.error("No indicators provided. Upload a file or enter IOCs manually.")
        else:
            run_pipeline(indicators_data, skip_enrichment=skip_enrich)

    # About
    st.markdown("---")
    st.markdown(
        """
        <div style="color: #64748b; font-size: 0.8rem;">
        <strong>ThreatWeave</strong> v0.1.0<br>
        Multi-Agent CTI Analysis<br>
        5 LLM agents • ATT&CK RAG<br>
        STIX 2.1 export
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Main area — Tabs
# ---------------------------------------------------------------------------
result = st.session_state.analysis_result
case = st.session_state.case
enriched = st.session_state.enriched_indicators

if result and result.get("report"):
    report = result["report"]

    # --- Metrics row ---
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📊 Indicators", len(case.indicators) if case else 0)
    with col2:
        st.metric("🎯 Techniques", len(report.technique_table))
    with col3:
        st.metric("🛡️ Sigma Rules", len(report.detection_rules))
    with col4:
        st.metric(
            "⏱️ Time",
            f"{st.session_state.processing_time:.1f}s",
        )

    # --- Tabs ---
    tab_analysis, tab_iocs, tab_export = st.tabs(
        ["📋 Analysis", "🔍 IOCs", "📦 Export"]
    )

    # ===== TAB 1: Analysis =====
    with tab_analysis:
        # Executive Summary
        with st.expander("📝 Executive Summary", expanded=True):
            st.markdown(report.executive_summary)

        # Detailed Analysis
        with st.expander("🔬 Detailed Analysis"):
            st.markdown(report.detailed_analysis)

        # Technique Mappings
        with st.expander(
            f"🎯 ATT&CK Technique Mappings ({len(report.technique_table)})",
            expanded=True,
        ):
            if report.technique_table:
                technique_data = []
                for t in report.technique_table:
                    technique_data.append(
                        {
                            "ID": t.technique_id,
                            "Name": t.technique_name,
                            "Tactic": t.tactic,
                            "Confidence": t.confidence,
                            "Evidence": t.evidence[:100] + "..."
                            if len(t.evidence) > 100
                            else t.evidence,
                        }
                    )
                st.dataframe(
                    technique_data,
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No technique mappings generated.")

        # Sigma Rules
        with st.expander(
            f"🛡️ Detection Rules ({len(report.detection_rules)})"
        ):
            for rule in report.detection_rules:
                st.markdown(f"**{rule.rule_title}** (`{rule.technique_id}`)")
                st.code(rule.rule_yaml, language="yaml")
                st.caption(f"Rationale: {rule.rationale}")
                st.divider()

        # Red Team
        with st.expander(
            f"🔴 Adversarial Considerations ({len(report.adversarial_considerations)})"
        ):
            for ev in report.adversarial_considerations:
                st.markdown(f"**Target:** {ev.target_rule}")
                st.markdown(f"**Evasion:** {ev.evasion_technique}")
                st.markdown(
                    f"**Difficulty:** `{ev.difficulty}` | **Hardening:** {ev.suggested_hardening}"
                )
                st.divider()

        # Recommendations
        with st.expander("✅ Recommended Actions", expanded=True):
            for action in report.recommended_actions:
                st.markdown(f"- {action}")

        # Validation
        with st.expander(
            f"✔️ Validation ({report.validation_status})"
        ):
            if report.validation_issues:
                for issue in report.validation_issues:
                    icon = "🔴" if issue.severity == "error" else "🟡"
                    st.markdown(
                        f"{icon} **{issue.check}** ({issue.severity}): {issue.detail}"
                    )
            else:
                st.success("All validation checks passed!")

    # ===== TAB 2: IOCs =====
    with tab_iocs:
        if enriched:
            ioc_data = []
            for ei in enriched:
                ind = ei.indicator
                row = {
                    "Type": ind.ioc_type,
                    "Value": ind.value,
                    "Source": ind.source,
                    "Context": ind.source_context[:60] if ind.source_context else "",
                    "Enrichment": ei.enrichment_status,
                }
                # Add enrichment highlights
                if "nvd" in ei.enrichment:
                    nvd = ei.enrichment["nvd"]
                    row["CVSS"] = nvd.get("cvss_score", "—")
                if "geo" in ei.enrichment:
                    geo = ei.enrichment["geo"]
                    row["Country"] = geo.get("country", "—")
                if "dns" in ei.enrichment:
                    dns = ei.enrichment["dns"]
                    a_records = dns.get("a_records", [])
                    row["A Records"] = ", ".join(a_records[:3]) if a_records else "—"

                ioc_data.append(row)

            st.dataframe(
                ioc_data,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("Run an analysis to see indicator details.")

    # ===== TAB 3: Export =====
    with tab_export:
        st.markdown("### Download Analysis Outputs")

        col_stix, col_json = st.columns(2)

        with col_json:
            st.markdown(
                """
                <div class="stix-info">
                <strong>📄 JSON Report</strong><br>
                Full structured report for UI integration
                </div>
                """,
                unsafe_allow_html=True,
            )
            from threatweave.export.json_report import export_json

            json_str = export_json(report)
            st.download_button(
                "📥 Download JSON Report",
                data=json_str,
                file_name=f"{report.report_id}.json",
                mime="application/json",
                use_container_width=True,
            )

        with col_stix:
            st.markdown(
                """
                <div class="stix-info">
                <strong>🔗 STIX 2.1 Bundle</strong><br>
                Machine-readable threat intelligence
                </div>
                """,
                unsafe_allow_html=True,
            )
            if case:
                try:
                    from threatweave.export.stix_builder import (
                        build_stix_bundle,
                    )

                    bundle = build_stix_bundle(case, report)
                    stix_str = json.dumps(bundle, indent=2, default=str)
                    st.download_button(
                        "📥 Download STIX Bundle",
                        data=stix_str,
                        file_name=f"{report.report_id}_stix.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"STIX export failed: {e}")

else:
    # Empty state
    st.markdown(
        """
        <div style="text-align: center; padding: 4rem 2rem; color: #64748b;">
            <h2 style="color: #94a3b8;">Welcome to ThreatWeave</h2>
            <p style="font-size: 1.1rem;">
                Upload an IOC file or enter indicators manually in the sidebar to begin analysis.
            </p>
            <p style="font-size: 0.9rem; margin-top: 1rem;">
                📂 Supported formats: JSON, CSV<br>
                🤖 5 specialized AI agents analyze your indicators<br>
                🎯 ATT&CK technique mapping with evidence<br>
                🛡️ Sigma detection rules generated automatically<br>
                📦 Export to STIX 2.1 and JSON
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
