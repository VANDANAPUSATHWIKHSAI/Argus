import sys
import json
import os
from pathlib import Path
import streamlit as st

# Ensure api_client can be imported from local directory
sys.path.insert(0, str(Path(__file__).parent))
import api_client

st.set_page_config(page_title="ARGUS Digital Forensics", layout="wide", initial_sidebar_state="expanded")

# --- SESSION STATE INITIALIZATION ---
if 'theme' not in st.session_state:
    st.session_state.theme = st.query_params.get("theme", "dark")

if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Dashboard'

if 'active_case_id' not in st.session_state:
    st.session_state.active_case_id = 'CASE-FINAL-DEMO-2026'

if 'active_tenant_id' not in st.session_state:
    st.session_state.active_tenant_id = 'default'


def set_page(page_name):
    st.session_state.current_page = page_name


# --- DYNAMIC THEME CSS ---
css_vars = '''
<style>
:root {
    --bg-main: #0b1120;
    --bg-card: #121826;
    --input-bg: #121826;
    --bg-alt: #0f1423;
    --bg-sidebar: #0f172a;
    --border-color: #1e293b;
    --border-light: #334155;
    --text-main: #f8fafc;
    --text-secondary: #e2e8f0;
    --text-muted: #cbd5e1;
    --text-dim: #94a3b8;
    --text-dimmer: #64748b;
    --hover-bg: rgba(30, 41, 59, 0.5);
    --shadow-1: rgba(0, 0, 0, 0.1);
    --primary-dark: #1e3a8a;
    --primary-light: #93c5fd;
    --primary-main: #3b82f6;
    --st-bg: #0b1120;
    --badge-high-bg: rgba(220, 38, 38, 0.2);
    --badge-high-text: #fca5a5;
    --badge-med-bg: rgba(245, 158, 11, 0.2);
    --badge-med-text: #fcd34d;
    --badge-low-bg: rgba(16, 185, 129, 0.2);
    --badge-low-text: #6ee7b7;
    --sev-high: #ef4444;
    --sev-med: #f59e0b;
    --sev-info: #3b82f6;
}
.stApp { background-color: var(--st-bg) !important; }
div[data-testid="stTabs"] button[data-baseweb="tab"] { color: var(--text-secondary) !important; border-bottom: 2px solid transparent; padding-bottom: 8px !important; }
div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] { color: var(--primary-main) !important; border-bottom: 2px solid var(--primary-main) !important; }
</style>
'''
if st.session_state.theme == "light":
    css_vars = '''
<style>
:root {
    --bg-main: #f8fafc;
    --bg-card: #ffffff;
    --input-bg: #FFFFFF;
    --bg-alt: #f1f5f9;
    --bg-sidebar: #ffffff;
    --border-color: #e2e8f0;
    --border-light: #cbd5e1;
    --text-main: #0f172a;
    --text-secondary: #1e293b;
    --text-muted: #334155;
    --text-dim: #475569;
    --text-dimmer: #64748b;
    --hover-bg: rgba(226, 232, 240, 0.5);
    --shadow-1: rgba(0, 0, 0, 0.05);
    --primary-dark: #2563eb;
    --primary-light: #ffffff;
    --primary-main: #2563eb;
    --st-bg: #f8fafc;
    --badge-high-bg: rgba(220, 38, 38, 0.1);
    --badge-high-text: #b91c1c;
    --badge-med-bg: rgba(245, 158, 11, 0.15);
    --badge-med-text: #b45309;
    --badge-low-bg: rgba(16, 185, 129, 0.1);
    --badge-low-text: #047857;
    --sev-high: #dc2626;
    --sev-med: #d97706;
    --sev-info: #2563eb;
}
.stApp { background-color: var(--st-bg) !important; color: var(--text-secondary) !important; }
</style>
'''
st.markdown(css_vars, unsafe_allow_html=True)


# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<div style='display: flex; align-items: center; gap: 12px; margin-top: 12px;'><div style='background-color: var(--primary-main); color: white; min-width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center;'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path></svg></div><div style='line-height: 1.2;'><strong style='color: var(--text-main); font-size: 16px; letter-spacing: 1px;'>ARGUS</strong><br><span style='color: var(--text-dim); font-size: 10px; letter-spacing: 0.5px;'>DIGITAL FORENSICS PLATFORM</span></div></div>", unsafe_allow_html=True)
    st.markdown("<div style='display: flex; align-items: center; gap: 12px; margin-top: 24px;'><div style='background-color: var(--primary-main); color: white; width: 32px; height: 32px; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: bold;'>JD</div><div style='line-height: 1.2;'><strong style='color: var(--text-main); font-size: 14px;'>John Doe</strong><br><span style='color: var(--text-dim); font-size: 12px;'>Forensic Analyst</span></div></div>", unsafe_allow_html=True)
    st.markdown("---")
    
    st.button("Dashboard", icon=":material/dashboard:", use_container_width=True, type="primary" if st.session_state.current_page == 'Dashboard' else "secondary", on_click=set_page, args=('Dashboard',))
    st.button("Evidence Upload", icon=":material/folder:", use_container_width=True, type="primary" if st.session_state.current_page == 'Evidence' else "secondary", on_click=set_page, args=('Evidence',))
    st.button("Investigation Timeline", icon=":material/timeline:", use_container_width=True, type="primary" if st.session_state.current_page == 'Timeline' else "secondary", on_click=set_page, args=('Timeline',))
    st.button("AI Findings / Assistant", icon=":material/smart_toy:", use_container_width=True, type="primary" if st.session_state.current_page == 'AI' else "secondary", on_click=set_page, args=('AI',))
    st.button("Report Builder", icon=":material/article:", use_container_width=True, type="primary" if st.session_state.current_page == 'Report' else "secondary", on_click=set_page, args=('Report',))
    
    st.markdown("---")
    st.markdown("<div style='color: var(--text-dim); font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 8px; letter-spacing: 0.5px;'>Active Case Configuration</div>", unsafe_allow_html=True)
    
    selected_case = st.text_input("Active Case ID", value=st.session_state.active_case_id, key="sidebar_case_input")
    if selected_case != st.session_state.active_case_id:
        st.session_state.active_case_id = selected_case.strip()
        st.rerun()

    selected_tenant = st.text_input("Tenant ID", value=st.session_state.active_tenant_id, key="sidebar_tenant_input")
    if selected_tenant != st.session_state.active_tenant_id:
        st.session_state.active_tenant_id = selected_tenant.strip()
        st.rerun()


# --- HEADER ---
h_left, h_center, h_right = st.columns([3, 4, 5])
with h_left:
    st.markdown(f"<div style='line-height: 1.2; margin-top: 8px;'><strong style='color: var(--text-main); font-size: 16px;'>{st.session_state.active_case_id}</strong><br><span style='color: var(--text-dim); font-size: 13px;'>Tenant: {st.session_state.active_tenant_id}</span></div>", unsafe_allow_html=True)

with h_center:
    st.text_input("Search", placeholder="Search across cases, evidence, findings...", label_visibility="collapsed")

with h_right:
    r1, r2, r3 = st.columns([1, 1, 4])
    with r1:
        st.markdown("<div style='text-align: center; color: var(--text-dim); cursor: pointer; margin-top: 8px;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9'></path><path d='M13.73 21a2 2 0 0 1-3.46 0'></path></svg></div>", unsafe_allow_html=True)
    with r2:
        st.markdown("<div style='text-align: center; color: var(--text-dim); cursor: pointer; margin-top: 8px;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><path d='M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3'></path><line x1='12' y1='17' x2='12.01' y2='17'></line></svg></div>", unsafe_allow_html=True)
    with r3:
        with st.popover("John Doe"):
            st.markdown("<strong style='color: var(--text-main);'>John Doe (Analyst)</strong>", unsafe_allow_html=True)
            is_dark_ui = st.toggle("Dark Mode", value=(st.session_state.theme == "dark"))
            if is_dark_ui != (st.session_state.theme == "dark"):
                st.session_state.theme = "dark" if is_dark_ui else "light"
                st.rerun()

st.markdown("---")


# ==========================================
# FETCH REAL BACKEND CASE DATA
# ==========================================
case_id = st.session_state.active_case_id
tenant_id = st.session_state.active_tenant_id

case_summary_res = api_client.get_case_summary(case_id, tenant_id)
report_json_res = api_client.get_report_json(case_id, allow_unreviewed=True, tenant_id=tenant_id)


# ==========================================
# 1. DASHBOARD PAGE
# ==========================================
if st.session_state.current_page == 'Dashboard':
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>1. Dashboard</h2>", unsafe_allow_html=True)

    if not case_summary_res["success"]:
        st.warning(f"⚠️ {case_summary_res['error']}")
        st.info(f"💡 You can upload evidence for case **{case_id}** on the Evidence Upload page or start the ARGUS backend server.")
    else:
        c_data = case_summary_res["data"]
        sev = c_data.get("severity_breakdown", {})
        
        tot_findings = c_data.get("total_findings", 0)
        high_cnt = sev.get("high", 0) + sev.get("critical", 0)
        med_cnt = sev.get("medium", 0)
        low_cnt = sev.get("low", 0) + sev.get("info", 0)
        artifacts_cnt = c_data.get("source_artifact_count", 0)
        latest_ts = c_data.get("latest_timestamp", "N/A")

        d_col1, d_col2 = st.columns([7, 3])

        with d_col1:
            st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px;'>CASE METRICS OVERVIEW</div>", unsafe_allow_html=True)
            oc1, oc2, oc3 = st.columns(3)
            with oc1:
                st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid var(--primary-main); border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">Source Artifacts</div>
    <div style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">{artifacts_cnt}</div>
    <div style="font-size: 11px; color: var(--text-dimmer); margin-top: 12px;">Stage 1/2 Evidence Artifacts</div>
</div>''', unsafe_allow_html=True)
            with oc2:
                st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #f59e0b; border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">Total Findings</div>
    <div style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">{tot_findings}</div>
    <div style="font-size: 11px; margin-top: 12px; display: flex; justify-content: space-between;"><span style="color:#ef4444">H: {high_cnt}</span><span style="color:#f59e0b">M: {med_cnt}</span><span style="color:#10b981">L: {low_cnt}</span></div>
</div>''', unsafe_allow_html=True)
            with oc3:
                st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #a855f7; border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">Latest Event</div>
    <div style="font-size: 14px; font-weight: 500; color: var(--text-main); line-height: 1.4; word-break: break-all;">{str(latest_ts)[:19]}</div>
    <div style="font-size: 11px; color: var(--text-dimmer); margin-top: 12px;">Authoritative Timestamp</div>
</div>''', unsafe_allow_html=True)

        with d_col2:
            st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px;'>ALERTS SEVERITY BREAKDOWN</div>", unsafe_allow_html=True)
            st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 16px; height: 100%; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border-color);">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #ef4444;"></div><span style="color: var(--text-secondary); font-size: 13px;">High / Critical</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">{high_cnt}</strong>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border-color);">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #f59e0b;"></div><span style="color: var(--text-secondary); font-size: 13px;">Medium</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">{med_cnt}</strong>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #10b981;"></div><span style="color: var(--text-secondary); font-size: 13px;">Low / Info</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">{low_cnt}</strong>
    </div>
</div>
''', unsafe_allow_html=True)

        st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

        # Real Findings Preview Table
        st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px;'>REAL FINDINGS (SANITIZED FACT VIEW)</div>", unsafe_allow_html=True)
        if report_json_res["success"] and "findings" in report_json_res["data"]:
            findings_list = report_json_res["data"]["findings"]
            if not findings_list:
                st.info("No findings generated for this case yet.")
            else:
                for idx, f in enumerate(findings_list[:5]):
                    s_bg = "#ef4444" if f.get("severity") in ("high", "critical") else "#f59e0b" if f.get("severity") == "medium" else "#10b981"
                    st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-left: 4px solid {s_bg}; border-radius: 6px; padding: 12px; margin-bottom: 8px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
        <span style="color: var(--text-main); font-size: 13px; font-weight: 600;">{f.get("sanitized_fact") or f.get("fact")}</span>
        <span style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{f.get("severity", "medium").upper()}</span>
    </div>
    <div style="display: flex; gap: 16px; color: var(--text-dim); font-size: 11px;">
        <span>Layer: {f.get("layer")}</span>
        <span>Confidence: {int(f.get("confidence", 1.0) * 100)}%</span>
        <span>MITRE: {f.get("mitre_mapping") or "N/A"}</span>
        <span>Status: {f.get("review_status")}</span>
    </div>
</div>
''', unsafe_allow_html=True)


# ==========================================
# 2. EVIDENCE UPLOAD PAGE
# ==========================================
elif st.session_state.current_page == 'Evidence':
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>2. Evidence Upload & Ingestion</h2>", unsafe_allow_html=True)

    st.markdown("### Upload Real Evidence File")
    uploaded_file = st.file_uploader("Upload Raw Forensic Evidence File (Disk Image, EVTX, PCAP, Email, Memory)", type=["E01", "aff", "evtx", "pcap", "eml", "msg", "xml", "json", "txt", "dmp"])
    
    if uploaded_file is not None:
        if st.button("Process Evidence via ARGUS Backend Pipeline", type="primary"):
            with st.spinner("Processing evidence file through ARGUS backend (Parsing → Normalization → Extraction → FCR → Analysis Engines → SanitizationGateway → FIR → PostgreSQL)..."):
                up_res = api_client.upload_evidence(uploaded_file.getvalue(), uploaded_file.name, case_id, tenant_id)
                if up_res["success"]:
                    st.success("✅ Evidence processed successfully by ARGUS backend pipeline!")
                    st.json(up_res["data"])
                else:
                    st.error(f"❌ Upload processing failed: {up_res['error']}")

    st.markdown("---")
    st.markdown("### Active Case Evidence Summary")
    if case_summary_res["success"]:
        c_data = case_summary_res["data"]
        st.markdown(f"**Case ID**: `{c_data.get('case_id')}` | **Tenant**: `{c_data.get('tenant_id')}` | **Source Artifact Count**: `{c_data.get('source_artifact_count')}`")


# ==========================================
# 3. AI FINDINGS & ASSISTANT PAGE
# ==========================================
elif st.session_state.current_page == 'AI':
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>3. AI Findings & Assistant</h2>", unsafe_allow_html=True)
    
    tab_f, tab_a = st.tabs(["AI Findings (FIR Backend)", "AI Assistant (Ollama / Evidence Query)"])
    
    with tab_f:
        if not report_json_res["success"]:
            st.warning(f"Unable to fetch findings: {report_json_res['error']}")
        else:
            findings_list = report_json_res["data"].get("findings", [])
            st.markdown(f"### Total Backend Findings: {len(findings_list)}")
            for idx, f in enumerate(findings_list):
                with st.expander(f"[{f.get('severity', 'medium').upper()}] {f.get('sanitized_fact') or f.get('fact')}", expanded=(idx == 0)):
                    st.markdown(f"**Sanitized Fact**: {f.get('sanitized_fact')}")
                    st.markdown(f"**Unsanitized Raw Fact**: `{f.get('fact')}`")
                    st.markdown(f"**Finding ID**: `{f.get('finding_id')}`")
                    st.markdown(f"**Fingerprint**: `{f.get('finding_fingerprint')}`")
                    st.markdown(f"**Confidence**: `{int(f.get('confidence', 1.0) * 100)}%` | **MITRE Mapping**: `{f.get('mitre_mapping') or 'N/A'}`")
                    st.markdown(f"**Analysis Layer**: `{f.get('layer')}` | **Source Artifact ID**: `{f.get('source_artifact_id')}`")
                    st.markdown(f"**Review Status**: `{f.get('review_status')}` | **Reviewed By**: `{f.get('reviewed_by') or 'None'}`")
                    st.markdown(f"**Prompt Injection Flagged**: `{f.get('injection_flagged')}` | **Injection Score**: `{f.get('injection_score', 0.0)}`")
                    if f.get("sanitization_actions"):
                        st.markdown(f"**Sanitization Actions Applied**: `{', '.join(f.get('sanitization_actions'))}`")

    with tab_a:
        st.markdown("### Query Case Evidence with AI Assistant")
        user_query = st.text_input("Ask a question about this case evidence:", key="query_input_field")
        if st.button("Submit Query", type="primary", key="query_submit_btn"):
            if not user_query.strip():
                st.warning("Please enter a non-empty query.")
            else:
                with st.spinner("Querying ARGUS case evidence..."):
                    q_res = api_client.query_case(case_id, user_query, tenant_id)
                    if q_res["success"]:
                        q_data = q_res["data"]
                        if q_data.get("fallback_mode"):
                            st.info("ℹ️ Ollama LLM is offline. Returning structured evidence summary fallback.")
                        st.markdown(f"**AI / Fallback Response**:\n\n{q_data.get('response') or q_data.get('answer')}")
                        if q_data.get("evidence_used"):
                            st.caption(f"Evidence Sources Used: {q_data.get('evidence_used')}")
                    else:
                        st.error(f"Query failed: {q_res['error']}")


# ==========================================
# 4. INVESTIGATION TIMELINE PAGE
# ==========================================
elif st.session_state.current_page == 'Timeline':
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>4. Unified Investigation Timeline</h2>", unsafe_allow_html=True)
    
    if report_json_res["success"]:
        findings_list = report_json_res["data"].get("findings", [])
        st.markdown(f"### Chronological Events ({len(findings_list)} timeline events)")
        for f in findings_list:
            st.markdown(f'''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; margin-bottom: 8px;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong style="color: var(--text-main); font-size: 13px;">{str(f.get("timestamp"))[:19]}</strong>
        <span style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{f.get("layer")}</span>
    </div>
    <div style="color: var(--text-secondary); font-size: 12px; margin-top: 4px;">{f.get("sanitized_fact") or f.get("fact")}</div>
</div>
''', unsafe_allow_html=True)


# ==========================================
# 5. REPORT BUILDER PAGE
# ==========================================
elif st.session_state.current_page == 'Report':
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>5. Report Generator & Export</h2>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### Export Structured Reports")
        
        # 1. JSON Export
        if report_json_res["success"]:
            json_str = json.dumps(report_json_res["data"], indent=2)
            st.download_button("Download Structured JSON Report", data=json_str, file_name=f"ARGUS_Report_{case_id}.json", mime="application/json", type="primary", use_container_width=True)

        st.markdown("---")

        # 2. HTML Export
        if st.button("Generate & Download HTML Report", use_container_width=True):
            h_res = api_client.get_report_html(case_id, allow_unreviewed=True, tenant_id=tenant_id)
            if h_res["success"]:
                st.download_button("Click to Download HTML File", data=h_res["html"], file_name=f"ARGUS_Report_{case_id}.html", mime="text/html", use_container_width=True)
            else:
                st.error(f"HTML generation failed: {h_res['error']}")

        st.markdown("---")

        # 3. PDF Export
        if st.button("Generate & Download PDF Report", use_container_width=True):
            pdf_bytes, pdf_err = api_client.get_report_pdf(case_id, allow_unreviewed=True, tenant_id=tenant_id)
            if pdf_bytes:
                st.download_button("Click to Download PDF File", data=pdf_bytes, file_name=f"ARGUS_Report_{case_id}.pdf", mime="application/pdf", use_container_width=True)
            else:
                st.warning(f"⚠️ {pdf_err}")
                st.info("💡 PDF rendering requires native GTK+/Pango libraries on Windows. Please use HTML or JSON export instead.")

    with col2:
        st.markdown("### HTML Report Live Preview")
        h_res = api_client.get_report_html(case_id, allow_unreviewed=True, tenant_id=tenant_id)
        if h_res["success"]:
            st.components.v1.html(h_res["html"], height=600, scrolling=True)
        else:
            st.warning("Report preview unavailable.")
