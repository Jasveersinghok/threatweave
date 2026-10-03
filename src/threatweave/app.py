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
# HuggingFace Dataset Sync
# ---------------------------------------------------------------------------
from threatweave.knowledge.hf_sync import sync_from_huggingface
sync_from_huggingface()

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
    .processing-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #0f2447 100%);
        border: 1px solid rgba(99, 102, 241, 0.35);
        border-radius: 16px;
        padding: 2.5rem 3rem;
        text-align: center;
        margin: 2rem auto;
        max-width: 700px;
    }
    .processing-title {
        color: #e2e8f0;
        font-size: 1.6rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    .processing-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-bottom: 2rem;
    }
    .ioc-preview-box {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 10px;
        padding: 1rem 1.4rem;
        text-align: left;
        font-family: monospace;
        font-size: 0.82rem;
        color: #a5b4fc;
        margin: 1.5rem 0;
        line-height: 1.7;
        white-space: pre-wrap;
    }
    .timer-box {
        display: inline-block;
        background: rgba(99, 102, 241, 0.12);
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 8px;
        padding: 0.5rem 1.2rem;
        color: #818cf8;
        font-size: 0.9rem;
        margin-top: 1rem;
    }
    .agent-pipeline {
        display: flex;
        justify-content: center;
        gap: 0.6rem;
        flex-wrap: wrap;
        margin: 1.5rem 0 0.5rem 0;
    }
    .agent-pill {
        background: rgba(99, 102, 241, 0.1);
        border: 1px solid rgba(99, 102, 241, 0.25);
        border-radius: 20px;
        padding: 0.3rem 0.9rem;
        color: #a5b4fc;
        font-size: 0.8rem;
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

    with st.status("🔄 Running ThreatWeave Pipeline... (Estimated time: ~400s)", expanded=True) as status:
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
# Main Area Routing
# ---------------------------------------------------------------------------
if "page" not in st.session_state:
    st.session_state.page = "input"
if "manual_input" not in st.session_state:
    st.session_state.manual_input = ""

if st.session_state.page == "input":
    st.markdown("### 📂 Input Indicators")
    
    st.markdown("**Quick test samples — click to load:**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("1 - IP + Hash", use_container_width=True):
            st.session_state.manual_input_key = (
                "ipv4, 185.220.101.47, Suspicious outbound C2 connection observed\n"
                "sha256, 5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef, Malware dropper hash from endpoint alert"
            )
            st.rerun()
    with col2:
        if st.button("2 - IP + Domain + CVE", use_container_width=True):
            st.session_state.manual_input_key = (
                "ipv4, 45.142.212.100, C2 server seen in post-exploitation traffic\n"
                "domain, update-service.net, Payload staging domain used in intrusion campaign\n"
                "cve, CVE-2021-44228, Log4Shell RCE vulnerability exploited for initial access"
            )
            st.rerun()
    with col3:
        if st.button("3 - Detailed Multi-IOC", use_container_width=True):
            st.session_state.manual_input_key = (
                "ipv4, 61.14.68.33, Source IP scanning Exchange for CVE-2023-23397 exploitation\n"
                "domain, mail-update.net, Phishing domain hosting credential harvesting page\n"
                "sha256, 44d88612fea8a8f36de82e1278abb02f, Cobalt Strike beacon observed on compromised host\n"
                "cve, CVE-2023-23397, Microsoft Outlook zero-click NTLM hash theft vulnerability\n"
                "domain, ntlm-relay.ru, Attacker-controlled server receiving stolen NTLM hashes"
            )
            st.rerun()

    col4, col5 = st.columns(2)
    with col4:
        if st.button("4 - SolarWinds / SUNBURST (APT29)", use_container_width=True):
            st.session_state.manual_input_key = (
                "domain, avsvmcloud.com, SUNBURST C2 domain used in SolarWinds supply chain attack\n"
                "ipv4, 13.59.205.66, APT29 C2 infrastructure associated with SUNBURST\n"
                "sha256, ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6, SUNBURST backdoor DLL\n"
                "cve, CVE-2020-10148, SolarWinds Orion API authentication bypass"
            )
            st.rerun()
    with col5:
        if st.button("5 - Fancy Bear / X-Agent (APT28)", use_container_width=True):
            st.session_state.manual_input_key = (
                "domain, account-login.org, APT28 credential phishing domain targeting government accounts\n"
                "sha256, d4be6c9117db9de76e6b425e3a3c82f2db06bd3af145e23e10def87b73bc4adc, X-Agent/Sofacy implant dropper\n"
                "ipv4, 191.101.31.6, APT28 C2 server hosting X-Agent malware"
            )
            st.rerun()

    _, center_col, _ = st.columns([1, 4, 1])
    with center_col:
        manual_iocs = st.text_area(
            "Enter IOCs (one per line, format: type, value, context)",
            height=160,
            placeholder="ipv4, 198.51.100.42, C2 server\ndomain, evil.com, Phishing site\nsha256, abc123..., Malware hash",
            key="manual_input_key",
        )

    st.markdown("---")
    uploaded_file = st.file_uploader(
        "Or upload IOC file",
        type=["json", "csv"],
        help="JSON array or CSV with columns: type, value, source, context",
    )

    skip_enrich = st.checkbox("Skip enrichment", value=False)

    if st.button("🚀 Analyze", type="primary", use_container_width=True):
        indicators_data = []

        if uploaded_file is not None:
            ext = Path(uploaded_file.name).suffix.lower()
            content_uploaded = uploaded_file.read().decode("utf-8")

            if ext == ".json":
                indicators_data = json.loads(content_uploaded)
            elif ext == ".csv":
                import csv
                from io import StringIO
                reader = csv.DictReader(StringIO(content_uploaded))
                for row in reader:
                    indicators_data.append(
                        {
                            "type": row.get("type", ""),
                            "value": row.get("value", ""),
                            "source": row.get("source", "file"),
                            "context": row.get("context", ""),
                        }
                    )

        if st.session_state.manual_input_key.strip():
            for line in st.session_state.manual_input_key.strip().split("\n"):
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
            st.session_state.indicators_data_to_run = indicators_data
            st.session_state.skip_enrich_to_run = skip_enrich
            st.session_state.page = "processing"
            st.rerun()

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

elif st.session_state.page == "processing":
    # ── Build IOC preview text ────────────────────────────────────────────
    raw_iocs = st.session_state.get("indicators_data_to_run", [])
    ioc_lines = []
    for ioc in raw_iocs:
        t = ioc.get("type", "")
        v = ioc.get("value", "")
        c = ioc.get("context", "")
        ioc_lines.append(f"  {t:<8}  {v:<55}  {c}" if c else f"  {t:<8}  {v}")
    ioc_preview = "\n".join(ioc_lines) if ioc_lines else "  (no indicators)"

    # ── Professional processing card ──────────────────────────────────────
    st.markdown(
        f"""
        <div class="processing-card">
            <div class="processing-title">&#x1F9E0; Multi-Agent Analysis Running</div>
            <div class="processing-subtitle">ThreatWeave is orchestrating 5 specialized AI agents across your indicators</div>
            <div class="ioc-preview-box"><b>Indicators being analysed ({len(raw_iocs)}):</b>\n{ioc_preview}</div>
            <div class="agent-pipeline">
                <span class="agent-pill">&#x1F50D; Analyst</span>
                <span class="agent-pill">&#x25B6; &#x25B6;</span>
                <span class="agent-pill">&#x1F3AF; Hunter</span>
                <span class="agent-pill">&#x25B6; &#x25B6;</span>
                <span class="agent-pill">&#x2694;&#xFE0F; Red Team</span>
                <span class="agent-pill">&#x25B6; &#x25B6;</span>
                <span class="agent-pill">&#x2705; Validator</span>
                <span class="agent-pill">&#x25B6; &#x25B6;</span>
                <span class="agent-pill">&#x1F4C4; Reporter</span>
            </div>
            <div class="timer-box">&#x23F1; Estimated completion time &nbsp;~&nbsp;<b>400 seconds</b> &nbsp;|&nbsp; Groq API + ATT&amp;CK RAG retrieval</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.spinner("Running pipeline — please do not close this tab..."):
        run_pipeline(
            st.session_state.indicators_data_to_run,
            skip_enrichment=st.session_state.skip_enrich_to_run,
        )

    st.session_state.page = "report"
    st.rerun()

elif st.session_state.page == "report":
    if st.button("⬅️ Start New Analysis", use_container_width=True):
        st.session_state.page = "input"
        st.session_state.manual_input = ""
        st.session_state.analysis_result = None
        st.rerun()
    st.markdown("---")

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
        # Error state
        st.error("Analysis Failed")
        st.markdown("The pipeline encountered errors during execution.")
    
        if result and "errors" in result:
            for err in result["errors"]:
                st.error(err)
            
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Retry Analysis", type="primary", use_container_width=True):
                st.session_state.page = "processing"
                st.rerun()
        with col2:
            if st.button("⬅️ Start Over", use_container_width=True):
                st.session_state.page = "input"
                st.session_state.manual_input = ""
                st.session_state.analysis_result = None
                st.rerun()
