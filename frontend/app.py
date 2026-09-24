import streamlit as st

st.set_page_config(page_title="ARGUS Digital Forensics", layout="wide", initial_sidebar_state="expanded")

import os
import requests
import json

API_BASE_URL = os.getenv("ARGUS_API_URL", "http://localhost:8000")

def check_backend_api():
    try:
        resp = requests.get(f"{API_BASE_URL}/", timeout=2)
        if resp.status_code == 200:
            return True, resp.json()
        return False, None
    except Exception:
        return False, None

def api_upload_evidence(file_obj, case_id=None, tenant_id="default"):
    try:
        files = {"file": (file_obj.name, file_obj.getvalue(), file_obj.type or "application/octet-stream")}
        data = {}
        if case_id:
            data["case_id"] = case_id
        headers = {"X-Tenant-ID": tenant_id}
        resp = requests.post(f"{API_BASE_URL}/evidence/upload", files=files, data=data, headers=headers, timeout=120)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"status": "ERROR", "error": f"API returned HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def api_get_case(case_id, tenant_id="default"):
    try:
        headers = {"X-Tenant-ID": tenant_id}
        resp = requests.get(f"{API_BASE_URL}/cases/{case_id}", headers=headers, timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

def api_query_case(case_id, query_str, tenant_id="default"):
    try:
        headers = {"X-Tenant-ID": tenant_id}
        resp = requests.post(f"{API_BASE_URL}/cases/{case_id}/query", json={"query": query_str}, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        return {"response": f"API Error {resp.status_code}: {resp.text}", "injection_flagged": False, "injection_score": 0.0}
    except Exception as e:
        return {"response": f"Connection error to backend API ({e})", "injection_flagged": False, "injection_score": 0.0}

def api_get_report(case_id, fmt="html", tenant_id="default"):
    try:
        headers = {"X-Tenant-ID": tenant_id}
        resp = requests.get(f"{API_BASE_URL}/reports/{case_id}/report?format={fmt}", headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.content, resp.headers.get("content-type", "text/html")
        return None, None
    except Exception:
        return None, None



if 'theme' not in st.session_state:
    st.session_state.theme = st.query_params.get("theme", "dark")
    



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
    --shadow-2: rgba(0, 0, 0, 0.06);
    --shadow-3: rgba(0, 0, 0, 0.5);
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
    --tag-blue-bg: rgba(59, 130, 246, 0.2);
    --tag-blue-text: #93c5fd;
    --tag-purple-bg: rgba(168, 85, 247, 0.2);
    --tag-purple-text: #d8b4fe;
    --tag-orange-bg: rgba(249, 115, 22, 0.2);
    --tag-orange-text: #fdba74;
    --tag-yellow-bg: rgba(234, 179, 8, 0.2);
    --tag-yellow-text: #fde047;
    --sev-high: #ef4444;
    --sev-med: #f59e0b;
    --sev-info: #3b82f6;
}
/* Ensure Streamlit background matches */
.stApp { background-color: var(--st-bg) !important; }

/* Fix Tabs Styling */
div[data-testid="stTabs"] button[data-baseweb="tab"] { color: var(--text-secondary) !important; border-bottom: 2px solid transparent; padding-bottom: 8px !important; }
div[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] { color: var(--primary-main) !important; border-bottom: 2px solid var(--primary-main) !important; }
div[data-testid="stTabs"] div[data-baseweb="tab-highlight"] { background-color: transparent !important; }

    /* Toggle visibility fix for stToggle */
    div[data-testid="stToggle"] div[data-baseweb="checkbox"] > div:first-child {
        background-color: var(--border-light) !important;
    }
    div[data-testid="stToggle"] input:checked + div > div, 
    div[data-testid="stToggle"] [aria-checked="true"] > div:first-child,
    div[data-testid="stToggle"] [data-checked="true"] > div:first-child {
        background-color: var(--primary-main) !important;
    }
    div[data-testid="stToggle"] div[data-baseweb="checkbox"] > div > div {
        background-color: #ffffff !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.3) !important;
    }

        /* JD Avatar Injection for Popover */
        [data-testid="stPopover"] button p::before {
            content: "JD";
            display: inline-block;
            background-color: var(--primary-main);
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 4px;
            text-align: center;
            line-height: 20px;
            font-size: 10px;
            font-weight: bold;
            margin-right: 8px;
            vertical-align: middle;
        }
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
    --shadow-2: rgba(0, 0, 0, 0.03);
    --shadow-3: rgba(0, 0, 0, 0.1);
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
    --tag-blue-bg: rgba(59, 130, 246, 0.1);
    --tag-blue-text: #1d4ed8;
    --tag-purple-bg: rgba(168, 85, 247, 0.1);
    --tag-purple-text: #7e22ce;
    --tag-orange-bg: rgba(249, 115, 22, 0.1);
    --tag-orange-text: #c2410c;
    --tag-yellow-bg: rgba(234, 179, 8, 0.15);
    --tag-yellow-text: #a16207;
    --sev-high: #dc2626;
    --sev-med: #d97706;
    --sev-info: #2563eb;
}
/* Override Streamlit native elements for light mode */
        .stApp { background-color: var(--st-bg) !important; color: var(--text-secondary) !important; }
        
        

/* BULLETPROOF SEARCH BAR */
        /* Use the wildcard to FORCE the background on all Streamlit shadow DOM elements */
        [data-testid="stTextInput"], [data-testid="stTextInput"] * {
            background-color: var(--input-bg) !important;
            border-color: var(--border-color) !important;
        }
        
        /* The actual input field */
        [data-testid="stTextInput"] input {
            background-color: transparent !important;
            color: var(--text-main) !important;
            -webkit-text-fill-color: var(--text-main) !important;
        }
        [data-testid="stTextInput"] input::placeholder {
            color: var(--text-muted) !important;
            -webkit-text-fill-color: var(--text-muted) !important;
            background-color: transparent !important;
        }
        
        /* CRITICAL: Explicitly EXCLUDE the helper text from the wildcard's background color! */
        [data-testid="InputInstructions"], 
        [data-testid="InputInstructions"] * {
            background-color: transparent !important;
            border-color: transparent !important;
            color: var(--text-dim) !important;
        }
        
        /* Helper text "Press Enter to apply" positioning and visibility */
        [data-testid="InputInstructions"] {
            position: absolute !important;
            bottom: -20px !important;
            right: 0px !important;
            font-size: 10px !important;
        }
        /* BULLETPROOF POPOVER BUTTON */
        [data-testid="stPopover"] button, [data-testid="stPopover"],
        [data-testid="stPopover"] button > div,
        [data-testid="stPopover"] button p {
            background-color: var(--bg-card) !important;
            color: var(--text-main) !important;
            border-color: var(--border-color) !important;
        }
        [data-testid="stPopover"] button svg {
            stroke: var(--text-main) !important;
            fill: var(--text-main) !important;
        }

        [data-testid="stSidebar"] { background-color: var(--bg-sidebar) !important; }
        [data-testid="stCheckbox"] label { color: var(--text-secondary) !important; }
        [data-testid="stSelectbox"] label { color: var(--text-secondary) !important; }
        [data-testid="stSelectbox"] div[data-baseweb="select"] > div { background-color: var(--bg-card) !important; border-color: var(--border-color) !important; color: var(--text-main) !important; }
        button[kind="secondary"] { background-color: var(--bg-card) !important; border-color: var(--border-color) !important; color: var(--text-main) !important; }
        button[kind="secondary"]:hover { background-color: var(--hover-bg) !important; }
        div[data-testid="stPopoverBody"] { background-color: var(--bg-sidebar) !important; border-color: var(--border-color) !important; box-shadow: 0 4px 6px -1px var(--shadow-1) !important; }
        div[data-testid="stPopoverBody"] .stButton button { color: var(--text-secondary) !important; }
        div[data-testid="stPopoverBody"] .stButton button:hover { background-color: var(--hover-bg) !important; color: var(--text-main) !important; }
        
        </style>
    '''

st.markdown(css_vars, unsafe_allow_html=True)

if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Dashboard'

def set_page(page_name):
    st.session_state.current_page = page_name


st.markdown("""\n<style>
/* GLOBAL TOGGLE VISIBILITY */

/* PARANOID FALLBACK FOR TOGGLE VISIBILITY */
div[data-testid="stToggle"] div[data-baseweb="checkbox"] > div:first-child {
    background-color: #94a3b8 !important;
}
div[data-testid="stToggle"] input:checked + div[data-baseweb="checkbox"] > div:first-child,
div[data-testid="stToggle"] input:checked + div > div:first-child {
    background-color: var(--primary-main) !important;
}
div[data-testid="stToggle"] div[data-baseweb="checkbox"] > div:first-child > div {
    background-color: #ffffff !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4) !important;
}

div[data-testid="stToggle"] label > div:first-of-type {
    background-color: #94a3b8 !important;
    border-radius: 9999px !important;
}
div[data-testid="stToggle"] input:checked + div:first-of-type {
    background-color: var(--primary-main) !important;
}
div[data-testid="stToggle"] label > div:first-of-type > div {
    background-color: #ffffff !important;
    border-radius: 50% !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4) !important;
    border: 1px solid #e2e8f0 !important;
}
</style>
\n""", unsafe_allow_html=True)


st.markdown("""
<style>
    /* Remove Streamlit's massive default top padding */
    .block-container { padding-top: 1rem !important; padding-bottom: 1rem !important; max-width: 100% !important; }
    
    /* Enable and style collapsedControl so sidebar toggle arrow is always visible */
    [data-testid="collapsedControl"] {
        display: flex !important;
        position: fixed !important;
        top: 12px !important;
        left: 12px !important;
        z-index: 999999 !important;
        background-color: #3b82f6 !important;
        color: white !important;
        border-radius: 6px !important;
        padding: 4px 8px !important;
    }
    [data-testid="collapsedControl"] button {
        color: white !important;
    }
    
    header[data-testid="stHeader"] {
        display: block !important;
        background: transparent !important;
    }
    /* Popover Dropdown Styling */
    div[data-testid="stPopoverBody"] {
        width: 320px !important;
        background-color: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        box-shadow: 0 10px 15px -3px var(--shadow-1) !important;
        user-select: none !important;
    }
    
    div[data-testid="stPopoverBody"] hr {
        margin: 8px 0px !important;
        border-color: var(--border-light) !important;
    }
    
    div[data-testid="stPopoverBody"] button[kind="secondary"] {
        justify-content: flex-start !important;
        border: none !important;
        background-color: transparent !important;
        padding: 6px 12px !important;
        height: auto !important;
        min-height: 36px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        color: var(--text-secondary) !important;
    }
    
    div[data-testid="stPopoverBody"] button[kind="secondary"]:hover {
        background-color: var(--hover-bg) !important;
        color: var(--text-main) !important;
    }
    
    /* Logout button styling - Red via primary override */
    div[data-testid="stPopoverBody"] .stButton button[kind="primary"] {
        justify-content: flex-start !important;
        border: none !important;
        background-color: transparent !important;
        padding: 6px 12px !important;
        height: auto !important;
        min-height: 36px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        color: #ef4444 !important;
    }
    
    div[data-testid="stPopoverBody"] .stButton button[kind="primary"]:hover {
        background-color: rgba(239, 68, 68, 0.1) !important;
    }
    
    
    /* Toggle visibility fix */
    div[data-testid="stCheckbox"] div[data-baseweb="checkbox"] > div:first-child {
        background-color: var(--border-light) !important;
    }
    div[data-testid="stCheckbox"] input:checked + div > div, 
    div[data-testid="stCheckbox"] [aria-checked="true"] > div:first-child,
    div[data-testid="stCheckbox"] [data-checked="true"] > div:first-child {
        background-color: var(--primary-main) !important;
    }
    div[data-testid="stCheckbox"] div[data-baseweb="checkbox"] > div > div {
        background-color: #ffffff !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.3) !important;
    }
/* Ensure the toggle doesn't wrap awkwardly */
    div[data-testid="stPopoverBody"] div[data-testid="stCheckbox"] {
        justify-content: flex-end !important;
    }
</style>
""", unsafe_allow_html=True)


st.markdown("""
<style>
    [data-testid="collapsedControl"] { display: none; }
    [data-testid="stSidebar"] {
        background-color: var(--bg-main) !important;
        border-right: 1px solid var(--border-color);
    }
    
    [data-testid="stSidebar"] .stButton button {
        padding: 8px 12px !important;
        min-height: 36px !important;
        height: 36px !important;
        border-radius: 6px !important;
        justify-content: flex-start !important;
        border: none !important;
        font-weight: 500 !important;
        font-size: 14px !important;
        margin-bottom: 4px !important;
    }
    
    [data-testid="stSidebar"] .stButton button[kind="primary"] {
        background-color: var(--primary-dark) !important;
        color: var(--primary-light) !important;
    }
    [data-testid="stSidebar"] button[kind="secondary"] {
        background-color: transparent !important;
        color: var(--text-dim) !important;
    }
    [data-testid="stSidebar"] button[kind="secondary"]:hover {
        background-color: var(--border-color) !important;
        color: var(--text-main) !important;
    }
    [data-testid="stSidebar"] hr {
        margin: 16px 0px;
        border-color: var(--border-color);
    }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<div style='display: flex; align-items: center; gap: 12px; margin-top: 12px;'><div style='background-color: var(--primary-main); color: white; min-width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center;'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'></path></svg></div><div style='line-height: 1.2;'><strong style='color: var(--text-main); font-size: 16px; letter-spacing: 1px;'>ARGUS</strong><br><span style='color: var(--text-dim); font-size: 10px; letter-spacing: 0.5px;'>DIGITAL FORENSICS</span></div></div>", unsafe_allow_html=True)

    st.markdown("<div style='display: flex; align-items: center; gap: 12px; margin-top: 24px;'><div style='background-color: var(--primary-main); color: white; width: 32px; height: 32px; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: bold;'>JD</div><div style='line-height: 1.2;'><strong style='color: var(--text-main); font-size: 14px;'>John Doe</strong><br><span style='color: var(--text-dim); font-size: 12px;'>Analyst</span></div></div>", unsafe_allow_html=True)
        
    st.markdown("---")
    
    st.button("Dashboard", icon=":material/dashboard:", use_container_width=True, type="primary" if st.session_state.current_page == 'Dashboard' else "secondary", on_click=set_page, args=('Dashboard',))
    st.button("Evidence", icon=":material/folder:", use_container_width=True, type="primary" if st.session_state.current_page == 'Evidence' else "secondary", on_click=set_page, args=('Evidence',))
    st.button("Investigation Timeline", icon=":material/timeline:", use_container_width=True, type="primary" if st.session_state.current_page == 'Timeline' else "secondary", on_click=set_page, args=('Timeline',))
    st.button("AI Findings / Assistant", icon=":material/smart_toy:", use_container_width=True, type="primary" if st.session_state.current_page == 'AI' else "secondary", on_click=set_page, args=('AI',))
    st.button("Report Builder", icon=":material/article:", use_container_width=True, type="primary" if st.session_state.current_page == 'Report' else "secondary", on_click=set_page, args=('Report',))
    st.button("Case Notes", icon=":material/notes:", use_container_width=True, type="primary" if st.session_state.current_page == 'Notes' else "secondary", on_click=set_page, args=('Notes',))
    
    st.markdown("---")
    
    st.markdown("<div style='color: var(--text-dim); font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 0.5px;'>Case Info</div>", unsafe_allow_html=True)
    st.markdown("""<div style='font-size: 13px; color: var(--text-dim); line-height: 1.6;'><div style='display: flex;'><span style='width: 80px; flex-shrink: 0;'>Case ID:</span><strong style='color:var(--text-main);'>CASE-2025-0007</strong></div><div style='display: flex; margin-top: 4px;'><span style='width: 80px; flex-shrink: 0;'>Case Title:</span><strong style='color:var(--text-main);'>Corporate Workstation Compromise</strong></div><div style='display: flex; margin-top: 4px;'><span style='width: 80px; flex-shrink: 0;'>Status:</span><span style='color:#10b981; font-weight: 600;'>● In Progress</span></div><div style='display: flex; margin-top: 4px;'><span style='width: 80px; flex-shrink: 0;'>Investigator:</span><strong style='color:var(--text-main);'>John Doe (Analyst)</strong></div><div style='display: flex; margin-top: 4px;'><span style='width: 80px; flex-shrink: 0;'>Started:</span><strong style='color:var(--text-main);'>25 May 2025 09:15 AM</strong></div><div style='display: flex; margin-top: 4px;'><span style='width: 80px; flex-shrink: 0;'>Updated:</span><strong style='color:var(--text-main);'>25 May 2025 11:47 AM</strong></div></div>""", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("<div style='color: var(--text-dim); font-size: 11px; font-weight: 600; text-transform: uppercase; margin-bottom: 8px; letter-spacing: 0.5px;'>FastAPI Backend Status</div>", unsafe_allow_html=True)
    api_online, api_info = check_backend_api()
    if api_online:
        st.success(f"🟢 API Online ({API_BASE_URL})")
    else:
        st.info(f"🟡 Standalone / Mock Mode (Start FastAPI at {API_BASE_URL})")

    st.button("Need Help?", icon=":material/help_center:", use_container_width=True, type="secondary")


# --- HEADER ---
h_left, h_center, h_right = st.columns([3, 4, 5])
with h_left:
    st.markdown("<div style='line-height: 1.2; margin-top: 8px;'><strong style='color: var(--text-main); font-size: 16px;'>CASE-2025-0007</strong><br><span style='color: var(--text-dim); font-size: 13px;'>Corporate Workstation Compromise</span></div>", unsafe_allow_html=True)

with h_center:
    st.text_input("Search", placeholder="Search across cases, evidence, findings...", label_visibility="collapsed")

with h_right:
    r1, r2, r3, r4 = st.columns([1, 1, 1, 5])
    with r1:
        st.markdown("<div style='text-align: center; color: var(--text-dim); cursor: pointer; margin-top: 8px;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9'></path><path d='M13.73 21a2 2 0 0 1-3.46 0'></path></svg></div>", unsafe_allow_html=True)
    with r2:
        st.markdown("<div style='text-align: center; color: var(--text-dim); cursor: pointer; margin-top: 8px;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><path d='M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3'></path><line x1='12' y1='17' x2='12.01' y2='17'></line></svg></div>", unsafe_allow_html=True)
    with r3:
        st.markdown("<div style='text-align: center; color: var(--text-dim); cursor: pointer; margin-top: 8px;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='3'></circle><path d='M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z'></path></svg></div>", unsafe_allow_html=True)
    with r4:
        with st.popover("John Doe"):
            st.markdown("""
            <div style='display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 0px 0 8px 0;'>
                <div style='background-color: var(--primary-main); color: white; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 15px; font-weight: bold; margin-bottom: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);'>JD</div>
                <strong style='color: var(--text-main); font-size: 15px; letter-spacing: 0.5px;'>John Doe</strong>
                <span style='color: var(--text-dim); font-size: 12px; margin-top: 2px;'>Analyst</span>
            </div>
            """, unsafe_allow_html=True)
            
            st.divider()
            
            st.button("My Profile", icon=":material/person:", use_container_width=True)
            st.button("Preferences", icon=":material/settings:", use_container_width=True)
            st.button("Change Password", icon=":material/key:", use_container_width=True)
            st.button("Notifications", icon=":material/notifications:", use_container_width=True)
            st.button("Help & Support", icon=":material/help:", use_container_width=True)
            
            st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
            
            # Custom Dark Mode Row
            c_t1, c_t2 = st.columns([7, 3], vertical_alignment="center")
            with c_t1:
                st.markdown("<div style='display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 14px; font-weight: 500; padding-left: 6px; user-select: none;'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z'></path></svg> Dark Mode</div>", unsafe_allow_html=True)
            with c_t2:
                is_dark_ui = st.toggle("Dark Mode", value=(st.session_state.theme == "dark"), label_visibility="collapsed")
                if is_dark_ui != (st.session_state.theme == "dark"):
                    st.session_state.theme = "dark" if is_dark_ui else "light"
                    try:
                        st.query_params["theme"] = st.session_state.theme
                    except:
                        pass
                    st.rerun()
            
            st.divider()
            
            st.markdown("---")

# --- TOP NAVIGATION BAR ---
nav_col1, nav_col2, nav_col3, nav_col4, nav_col5, nav_col6 = st.columns(6)
with nav_col1:
    st.button("📊 Dashboard", type="primary" if st.session_state.current_page == 'Dashboard' else "secondary", use_container_width=True, on_click=set_page, args=('Dashboard',), key="top_nav_dash")
with nav_col2:
    st.button("📁 Evidence", type="primary" if st.session_state.current_page == 'Evidence' else "secondary", use_container_width=True, on_click=set_page, args=('Evidence',), key="top_nav_ev")
with nav_col3:
    st.button("⏱️ Timeline", type="primary" if st.session_state.current_page == 'Timeline' else "secondary", use_container_width=True, on_click=set_page, args=('Timeline',), key="top_nav_tl")
with nav_col4:
    st.button("🤖 AI Assistant", type="primary" if st.session_state.current_page == 'AI' else "secondary", use_container_width=True, on_click=set_page, args=('AI',), key="top_nav_ai")
with nav_col5:
    st.button("📄 Report Builder", type="primary" if st.session_state.current_page == 'Report' else "secondary", use_container_width=True, on_click=set_page, args=('Report',), key="top_nav_rep")
with nav_col6:
    st.button("📝 Case Notes", type="primary" if st.session_state.current_page == 'Notes' else "secondary", use_container_width=True, on_click=set_page, args=('Notes',), key="top_nav_notes")
st.markdown("---")


if st.session_state.current_page == 'Dashboard':
    # ==========================================
    # 1. DASHBOARD
    # ==========================================
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>1. Dashboard</h2>", unsafe_allow_html=True)

    d_col1, d_col2 = st.columns([7, 3])

    with d_col1:
        st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px; letter-spacing: 0.5px;'>HIGH PRIORITY ALERTS</div>", unsafe_allow_html=True)
        ac1, ac2, ac3 = st.columns(3)
        with ac1:
            st.markdown('''
<div style="background-color: rgba(127, 29, 29, 0.15); border: 1px solid rgba(220, 38, 38, 0.3); border-radius: 6px; padding: 16px; height: 100%; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        <span style="color: #ef4444; font-size: 14px; font-weight: 600;">Malware Detected</span>
    </div>
    <div style="color: var(--text-dim); font-size: 12px; line-height: 1.4; margin-bottom: 16px; min-height: 34px;">Suspicious PowerShell execution detected</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--text-dimmer); font-size: 11px;">10:31 AM &middot; 25 May 2025</span>
        <span style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;">HIGH</span>
    </div>
</div>''', unsafe_allow_html=True)
        with ac2:
            st.markdown('''
<div style="background-color: rgba(127, 29, 29, 0.15); border: 1px solid rgba(220, 38, 38, 0.3); border-radius: 6px; padding: 16px; height: 100%; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        <span style="color: #ef4444; font-size: 14px; font-weight: 600;">Credential Access</span>
    </div>
    <div style="color: var(--text-dim); font-size: 12px; line-height: 1.4; margin-bottom: 16px; min-height: 34px;">Possible credential dumping detected</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--text-dimmer); font-size: 11px;">10:21 AM &middot; 25 May 2025</span>
        <span style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;">HIGH</span>
    </div>
</div>''', unsafe_allow_html=True)
        with ac3:
            st.markdown('''
<div style="background-color: rgba(146, 64, 14, 0.15); border: 1px solid rgba(217, 119, 6, 0.3); border-radius: 6px; padding: 16px; height: 100%; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="18" r="3"></circle><circle cx="6" cy="6" r="3"></circle><path d="M13 6h3a2 2 0 0 1 2 2v7"></path><line x1="6" y1="9" x2="6" y2="21"></line></svg>
        <span style="color: #f59e0b; font-size: 14px; font-weight: 600;">Lateral Movement</span>
    </div>
    <div style="color: var(--text-dim); font-size: 12px; line-height: 1.4; margin-bottom: 16px; min-height: 34px;">RDP connection to remote host detected</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--text-dimmer); font-size: 11px;">09:58 AM &middot; 25 May 2025</span>
        <span style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;">MEDIUM</span>
    </div>
</div>''', unsafe_allow_html=True)

    with d_col2:
        st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px; letter-spacing: 0.5px;'>ALERTS SUMMARY</div>", unsafe_allow_html=True)
        st.markdown('''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 16px; height: 100%; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #ef4444;"></div><span style="color: var(--text-secondary); font-size: 13px;">High</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">3</strong>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #f59e0b;"></div><span style="color: var(--text-secondary); font-size: 13px;">Medium</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">4</strong>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; align-items: center; gap: 8px;"><div style="width: 8px; height: 8px; border-radius: 50%; background-color: #10b981;"></div><span style="color: var(--text-secondary); font-size: 13px;">Low</span></div>
        <strong style="color: var(--text-main); font-size: 14px;">7</strong>
    </div>
</div>
''', unsafe_allow_html=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True) # Compact Spacer

    d_col3, d_col4 = st.columns([7, 3])

    with d_col3:
        st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px; letter-spacing: 0.5px;'>CASE OVERVIEW</div>", unsafe_allow_html=True)
        oc1, oc2, oc3 = st.columns(3)
        with oc1:
            st.markdown('''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid var(--primary-main); border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">Evidence Items</div>
    <div style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">12</div>
    <div style="font-size: 11px; color: var(--text-dimmer); margin-top: 12px; display: flex; justify-content: space-between;"><span>Ingested: 10</span><span>Processing: 2</span></div>
</div>''', unsafe_allow_html=True)
        with oc2:
            st.markdown('''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #f59e0b; border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">AI Findings</div>
    <div style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">17</div>
    <div style="font-size: 11px; margin-top: 12px; display: flex; justify-content: space-between;"><span style="color:#ef4444">H: 8</span><span style="color:#f59e0b">M: 6</span><span style="color:#10b981">L: 3</span></div>
</div>''', unsafe_allow_html=True)
        with oc3:
            st.markdown('''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #a855f7; border-radius: 6px; padding: 16px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="color: var(--text-dim); font-size: 12px; font-weight: 500; margin-bottom: 8px;">Notes</div>
    <div style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">8</div>
    <div style="font-size: 11px; color: var(--text-dimmer); margin-top: 12px;">Case Notes</div>
</div>''', unsafe_allow_html=True)

    with d_col4:
        col_ai_1, col_ai_2 = st.columns([7, 3])
        with col_ai_1:
            st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 12px; letter-spacing: 0.5px; margin-top: 4px;'>TOP AI FINDINGS</div>", unsafe_allow_html=True)
        with col_ai_2:
            if st.button("View all", type="tertiary", use_container_width=True, key="view_ai_btn"):
                set_page("AI")
                st.rerun()
        st.markdown('''
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; box-shadow: 0 4px 6px -1px var(--shadow-1);">
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); margin-bottom: 10px;">
        <div><div style="font-size: 12px; color: var(--text-secondary); font-weight: 500; margin-bottom: 2px;">Malicious PowerShell Exec</div><div style="font-size: 10px; color: var(--text-dimmer);">Confidence: 90%</div></div>
        <div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700;">HIGH</div>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); margin-bottom: 10px;">
        <div><div style="font-size: 12px; color: var(--text-secondary); font-weight: 500; margin-bottom: 2px;">Credential Dumping Act</div><div style="font-size: 10px; color: var(--text-dimmer);">Confidence: 90%</div></div>
        <div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700;">HIGH</div>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); margin-bottom: 10px;">
        <div><div style="font-size: 12px; color: var(--text-secondary); font-weight: 500; margin-bottom: 2px;">Suspicious Registry Mod</div><div style="font-size: 10px; color: var(--text-dimmer);">Confidence: 86%</div></div>
        <div style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700;">MEDIUM</div>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div><div style="font-size: 12px; color: var(--text-secondary); font-weight: 500; margin-bottom: 2px;">Outbound Connection</div><div style="font-size: 10px; color: var(--text-dimmer);">Confidence: 78%</div></div>
        <div style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700;">MEDIUM</div>
    </div>
</div>
''', unsafe_allow_html=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True) # Compact Spacer

    st.markdown("<div style='font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-dim); margin-bottom: 24px; letter-spacing: 0.5px;'>INVESTIGATION TIMELINE (CONDENSED)</div>", unsafe_allow_html=True)
    st.markdown('''
<div style="position: relative; margin-top: 16px; margin-bottom: 32px;"><!-- Connecting Line --><div style="position: absolute; top: 6px; left: 2%; right: 2%; height: 2px; background-color: var(--border-light); z-index: 1;"></div><div style="display: flex; justify-content: space-between; position: relative; z-index: 2;"><!-- Nodes --><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: var(--primary-main); border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">09:15 AM<br><strong style="color:var(--text-secondary);">Case<br>Started</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: var(--primary-main); border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">09:31 AM<br><strong style="color:var(--text-secondary);">Evidence<br>Uploaded</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: #f59e0b; border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">09:45 AM<br><strong style="color:var(--text-secondary);">Parsing<br>Completed</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: #ef4444; border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">10:05 AM<br><strong style="color:var(--text-secondary);">AI Analysis<br>Completed</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: #ef4444; border: 2px solid var(--bg-main); margin-bottom: 12px; box-shadow: 0 0 0 2px rgba(239,68,68,0.3);"></div><div style="font-size: 10px; color: #ef4444; text-align: center; line-height: 1.3;">10:31 AM<br><strong style="color:#ef4444;">High Priority<br>Alert</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: var(--primary-main); border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">10:45 AM<br><strong style="color:var(--text-secondary);">Investigation<br>In Progress</strong></div></div><div style="display: flex; flex-direction: column; align-items: center; width: 60px;"><div style="width: 14px; height: 14px; border-radius: 50%; background-color: #10b981; border: 2px solid var(--bg-main); margin-bottom: 12px;"></div><div style="font-size: 10px; color: var(--text-dim); text-align: center; line-height: 1.3;">11:30 AM<br><strong style="color:var(--text-secondary);">Note<br>Added</strong></div></div></div></div>
''', unsafe_allow_html=True)

elif st.session_state.current_page == 'Evidence':
    # ==========================================
    # 2. EVIDENCE PAGE
    # ==========================================
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>2. Evidence</h2>", unsafe_allow_html=True)

    with st.expander("📤 Live API Multi-File & Folder Evidence Upload", expanded=True):
        up_files = st.file_uploader(
            "Upload multiple raw evidence files or Folder Zip Archives (EVTX, PCAP, Memory Dumps, Registry, Logs, ZIP folders)",
            accept_multiple_files=True,
            type=None,
            key="live_ev_uploader"
        )
        up_case_id = st.text_input("Target Case ID", value="CASE-2025-0007", key="up_case_id_input")
        if up_files and st.button("Submit Batch / Folder to Argus Forensic Pipeline", type="primary", key="btn_run_pipeline"):
            total_arts, total_entities, total_fcrs, total_findings = 0, 0, 0, 0
            with st.spinner(f"Processing {len(up_files)} item(s) through 4-stage pipeline (Parsers -> Extractor -> FCR Engine -> FIR Storage)..."):
                for f_item in up_files:
                    res = api_upload_evidence(f_item, case_id=up_case_id)
                    if res.get("status") in ["SUCCESS", "PARTIAL_SUCCESS"]:
                        total_arts += res.get("parsed_artifact_count", 0)
                        total_entities += res.get("derived_observable_count", 0)
                        total_fcrs += res.get("fcr_count", 0)
                        total_findings += res.get("finding_count", 0)
                    else:
                        st.error(f"❌ Failed for file '{f_item.name}': {res.get('error', 'Unknown error')}")
            
            st.success(f"✅ Ingestion Complete for {len(up_files)} evidence file/folder items!")
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric("Total Artifacts Parsed", total_arts)
            col_b.metric("Entities Extracted", total_entities)
            col_c.metric("FCR Records", total_fcrs)
            col_d.metric("FIR Findings", total_findings)

    
    t_col1, t_col2, t_col3, t_col4 = st.columns([2,2,2,10])
    with t_col1:
        st.button("Evidence Items", type="primary", use_container_width=True)
    with t_col2:
        st.button("Upload Evidence", type="secondary", use_container_width=True)
    with t_col3:
        if st.button("Coverage", type="secondary", use_container_width=True):
            st.session_state.current_page = 'Coverage'
            st.rerun()

    st.markdown('''
    <!-- Metric Cards -->
    <div style="display: flex; gap: 16px; margin-top: 24px; margin-bottom: 32px;">
        <div class="ev-metric-box" style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid var(--primary-main); box-shadow: 0 4px 6px -1px var(--shadow-1); width: 20%; padding: 16px; border-radius: 8px;">
            <span style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px; font-weight: 500; display: block;">Total Items</span>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">12</span>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--primary-main)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path></svg>
            </div>
        </div>
        <div class="ev-metric-box" style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #10b981; box-shadow: 0 4px 6px -1px var(--shadow-1); width: 20%; padding: 16px; border-radius: 8px;">
            <span style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px; font-weight: 500; display: block;">Ingested</span>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">10</span>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            </div>
        </div>
        <div class="ev-metric-box" style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #f59e0b; box-shadow: 0 4px 6px -1px var(--shadow-1); width: 20%; padding: 16px; border-radius: 8px;">
            <span style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px; font-weight: 500; display: block;">Processing</span>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">2</span>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            </div>
        </div>
        <div class="ev-metric-box" style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid #ef4444; box-shadow: 0 4px 6px -1px var(--shadow-1); width: 20%; padding: 16px; border-radius: 8px;">
            <span style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px; font-weight: 500; display: block;">Failed</span>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">0</span>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            </div>
        </div>
        <div class="ev-metric-box" style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-top: 3px solid var(--text-dimmer); box-shadow: 0 4px 6px -1px var(--shadow-1); width: 20%; padding: 16px; border-radius: 8px;">
            <span style="color: var(--text-dim); font-size: 12px; margin-bottom: 8px; font-weight: 500; display: block;">Total Size</span>
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 32px; font-weight: 300; color: var(--text-main); line-height: 1;">1.24 <span style="font-size: 16px;">TB</span></span>
            </div>
        </div>
    </div>
    
    <!-- Filter Row -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; font-size: 12px;">
        <input type="text" placeholder="Search evidence..." style="background-color: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 12px; border-radius: 6px; width: 300px; outline: none; box-shadow: inset 0 1px 2px var(--shadow-1);">
        <div style="display: flex; gap: 8px; align-items: center;">
            <select style="background-color: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px; border-radius: 6px; outline: none;"><option>All Types</option></select>
            <select style="background-color: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px; border-radius: 6px; outline: none;"><option>All Status</option></select>
            <select style="background-color: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px; border-radius: 6px; outline: none;"><option>All Sources</option></select>
            <button style="background-color: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 16px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 6px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>
                Filters
            </button>
        </div>
    </div>
    
    <!-- Custom Table -->
    <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 0; box-shadow: 0 4px 6px -1px var(--shadow-1); overflow: hidden;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 0;">
            <thead style="background-color: var(--bg-main);">
                <tr>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Evidence Name</th>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Type</th>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Source</th>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Size</th>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Status</th>
                    <th style="padding: 16px; text-align: left; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border-color);">Added On</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="padding: 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-color);">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        <span style="color: var(--text-secondary); font-weight: 500;">Workstation-Memory.dmp</span>
                    </td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><span style="background-color: rgba(139, 92, 246, 0.15); color: var(--tag-purple-text); border: 1px solid rgba(139, 92, 246, 0.3); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">Memory Dump</span></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">Workstation-01</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">8.00 GB</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><div style="display: flex; align-items: center; gap: 6px;"><div style="width: 6px; height: 6px; border-radius: 50%; background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Ingested</span></div></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-dim); font-size: 12px;">25 May 2025<br>09:35 AM</td>
                </tr>
                <tr>
                    <td style="padding: 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-color);">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary-main)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        <span style="color: var(--text-secondary); font-weight: 500;">Workstation-01.pcap</span>
                    </td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><span style="background-color: rgba(59, 130, 246, 0.15); color: var(--primary-light); border: 1px solid rgba(59, 130, 246, 0.3); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">PCAP</span></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">Workstation-01</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">512 MB</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><div style="display: flex; align-items: center; gap: 6px;"><div style="width: 6px; height: 6px; border-radius: 50%; background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Ingested</span></div></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-dim); font-size: 12px;">25 May 2025<br>09:31 AM</td>
                </tr>
                <tr>
                    <td style="padding: 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-color);">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        <span style="color: var(--text-secondary); font-weight: 500;">Security_Event_Logs.evtx</span>
                    </td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><span style="background-color: var(--badge-low-bg); color: var(--badge-low-text); border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">Event Logs</span></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">Workstation-01</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">1.2 GB</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><div style="display: flex; align-items: center; gap: 6px;"><div style="width: 6px; height: 6px; border-radius: 50%; background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Ingested</span></div></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-dim); font-size: 12px;">25 May 2025<br>09:15 AM</td>
                </tr>
                <tr>
                    <td style="padding: 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border-color);">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        <span style="color: var(--text-secondary); font-weight: 500;">NTUSER.DAT</span>
                    </td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><span style="background-color: var(--badge-med-bg); color: var(--badge-med-text); border: 1px solid rgba(245, 158, 11, 0.3); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">Registry</span></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">Workstation-01</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">15 MB</td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color);"><div style="display: flex; align-items: center; gap: 6px;"><div style="width: 6px; height: 6px; border-radius: 50%; background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Processing</span></div></td>
                    <td style="padding: 16px; border-bottom: 1px solid var(--border-color); color: var(--text-dim); font-size: 12px;">25 May 2025<br>09:15 AM</td>
                </tr>
            </tbody>
        </table>
    </div>
    ''', unsafe_allow_html=True)

elif st.session_state.current_page == 'Coverage':
    # ==========================================
    # 3. COVERAGE PAGE
    # ==========================================
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>3. Coverage</h2>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs(["Coverage Overview", "Detailed Coverage", "Missing Artifacts", "Recommendations"])

    with tab1:
        st.markdown("""<style>.cov-table { width: 100%; border-collapse: collapse; font-size: 11px; } .cov-table th { text-align: left; padding: 6px 12px; color: var(--text-dim); border-bottom: 1px solid var(--border-color); font-weight: 500; } .cov-table td { padding: 6px 12px; border-bottom: 1px solid var(--border-color); color: var(--text-main); } .icon-box { width: 22px; height: 22px; border-radius: 4px; display: flex; align-items: center; justify-content: center; } .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }</style>
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 16px;">
<div style="color: var(--text-main); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 12px;">OVERALL COVERAGE</div>
<div style="display: flex; gap: 32px; align-items: center;">
<div style="width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#10b981 0% 78%, var(--border-color) 78% 100%); display: flex; align-items: center; justify-content: center; position: relative;">
<div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; border-radius: 50%; background: conic-gradient(transparent 0% 78%, #f59e0b 78% 93%, #ef4444 93% 100%);"></div>
<div style="width: 90px; height: 90px; border-radius: 50%; background-color: var(--bg-card); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 10;"><span style="font-size: 24px; font-weight: bold; color: var(--text-main);">78%</span><span style="font-size: 9px; color: var(--text-dim);">Overall Coverage</span></div>
</div>
<div style="display: flex; flex-direction: column; gap: 10px; width: 250px;">
<div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><div class="status-dot" style="background-color: #10b981;"></div><span style="color: var(--text-main); font-size: 12px;">Complete</span></div><span style="color: var(--text-main); font-size: 12px;">46 (78%)</span></div>
<div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: var(--text-main); font-size: 12px;">Partial</span></div><span style="color: var(--text-main); font-size: 12px;">9 (15%)</span></div>
<div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><div class="status-dot" style="background-color: #ef4444;"></div><span style="color: var(--text-main); font-size: 12px;">Missing</span></div><span style="color: var(--text-main); font-size: 12px;">4 (7%)</span></div>
<div style="display: flex; justify-content: space-between; align-items: center;"><div style="display: flex; align-items: center; gap: 8px;"><div class="status-dot" style="background-color: var(--text-dimmer);"></div><span style="color: var(--text-main); font-size: 12px;">Not Applicable</span></div><span style="color: var(--text-main); font-size: 12px;">0 (0%)</span></div>
</div></div></div>
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 16px;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
<div style="color: var(--text-main); font-size: 0.75rem; font-weight: 600; text-transform: uppercase;">COVERAGE BY ARTIFACT CATEGORY</div><div style="color: var(--primary-main); font-size: 11px; cursor: pointer;">View details</div>
</div>
<table class="cov-table">
<thead><tr><th style="width: 30%;">Category</th><th style="width: 30%;">Coverage</th><th style="width: 20%;">Status</th><th style="width: 20%;">Artifacts</th></tr></thead>
<tbody>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg></div>Memory Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 92%; height: 100%; background-color: #10b981; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">92%</span></div></td>
<td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Complete</span></td><td>8 / 8</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg></div>Registry Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 75%; height: 100%; background-color: #f59e0b; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">75%</span></div></td>
<td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Partial</span></td><td>18 / 24</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-teal-bg); color: var(--tag-teal-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg></div>Windows Event Logs</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 94%; height: 100%; background-color: #10b981; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">94%</span></div></td>
<td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Complete</span></td><td>15 / 16</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-orange-bg); color: var(--tag-orange-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg></div>Network Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 63%; height: 100%; background-color: #f59e0b; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">63%</span></div></td>
<td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Partial</span></td><td>6 / 10</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--badge-high-bg); color: var(--badge-high-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"></polygon></svg></div>Browser Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 60%; height: 100%; background-color: #f59e0b; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">60%</span></div></td>
<td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Partial</span></td><td>7 / 12</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-yellow-bg); color: var(--tag-yellow-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg></div>File System Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 94%; height: 100%; background-color: #10b981; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">94%</span></div></td>
<td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Complete</span></td><td>28 / 30</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--badge-low-bg); color: var(--badge-low-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg></div>Email Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 50%; height: 100%; background-color: #f59e0b; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">50%</span></div></td>
<td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Partial</span></td><td>3 / 6</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-orange-bg); color: var(--tag-orange-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg></div>Security Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 100%; height: 100%; background-color: #10b981; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">100%</span></div></td>
<td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981; font-weight: 500;">Complete</span></td><td>6 / 6</td>
</tr>
<tr>
<td style="display: flex; align-items: center; gap: 8px;"><div class="icon-box" style="background-color: var(--tag-orange-bg); color: var(--tag-orange-text);"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg></div>Other Artifacts</td>
<td><div style="display: flex; align-items: center; gap: 8px;"><div style="width: 100px; height: 4px; background-color: var(--border-color); border-radius: 2px;"><div style="width: 78%; height: 100%; background-color: #10b981; border-radius: 2px;"></div></div><span style="font-size: 11px; color: var(--text-dim);">78%</span></div></td>
<td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b; font-weight: 500;">Partial</span></td><td>11 / 14</td>
</tr>
</tbody>
</table></div>""", unsafe_allow_html=True)
        
        c_col1, c_col2 = st.columns([8, 2])
        with c_col1:
            st.markdown("""<div style="color: var(--text-dim); font-size: 11px; padding-top: 8px;">Last Updated: 25 May 2025 11:47 AM</div>""", unsafe_allow_html=True)
        with c_col2:
            st.button("Refresh Coverage", type="primary", use_container_width=True)

    with tab2:

            st.markdown("""
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
                <div style="color: var(--text-main); font-size: 14px; font-weight: 600; margin-bottom: 16px;">Memory Analysis Details</div>
                <table class="cov-table">
                    <thead><tr><th style="width: 25%;">Artifact</th><th style="width: 25%;">Plugin/Tool</th><th style="width: 30%;">Status</th><th style="width: 20%;">Extracted</th></tr></thead>
                    <tbody>
                        <tr><td>Process List</td><td>Volatility pslist</td><td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981;">Complete</span></td><td>42 items</td></tr>
                        <tr><td>Network Connections</td><td>Volatility netscan</td><td><div class="status-dot" style="background-color: #10b981;"></div><span style="color: #10b981;">Complete</span></td><td>18 items</td></tr>
                        <tr><td>Injected Code</td><td>Volatility malfind</td><td><div class="status-dot" style="background-color: #f59e0b;"></div><span style="color: #f59e0b;">Partial</span></td><td>3 items</td></tr>
                    </tbody>
                </table>
            </div>
            """, unsafe_allow_html=True)

    with tab3:

            st.markdown("""
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
                <div style="color: var(--text-main); font-size: 14px; font-weight: 600; margin-bottom: 16px;">Critical Missing Artifacts</div>
                <table class="cov-table">
                    <thead><tr><th style="width: 35%;">Missing Item</th><th style="width: 45%;">Impact</th><th style="width: 20%;">Severity</th></tr></thead>
                    <tbody>
                        <tr><td>IIS Access Logs</td><td>Cannot determine external web vector</td><td><span style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">HIGH</span></td></tr>
                        <tr><td>Firewall Dropped Packets</td><td>Limited visibility into lateral scanning</td><td><span style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">MEDIUM</span></td></tr>
                        <tr><td>Prefetch (Disabled)</td><td>Reduced timeline resolution for execution</td><td><span style="background-color: var(--badge-low-bg); color: var(--badge-low-text); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">LOW</span></td></tr>
                    </tbody>
                </table>
            </div>
            """, unsafe_allow_html=True)

    with tab4:

            st.markdown("""
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
                <div style="color: var(--text-main); font-size: 14px; font-weight: 600; margin-bottom: 16px;">Actionable Recommendations</div>
                <div style="border-left: 3px solid var(--sev-high); padding-left: 12px; margin-bottom: 16px;">
                    <div style="color: var(--text-main); font-weight: 500; font-size: 13px;">Deploy EDR to Server Subnet</div>
                    <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Lack of telemetry on internal servers hindered lateral movement tracking. Recommend immediate deployment of EDR.</div>
                </div>
                <div style="border-left: 3px solid var(--sev-med); padding-left: 12px; margin-bottom: 16px;">
                    <div style="color: var(--text-main); font-weight: 500; font-size: 13px;">Enable Windows PowerShell Logging</div>
                    <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Script Block Logging (Event ID 4104) is currently disabled via GPO. Enable it to capture deobfuscated payload execution.</div>
                </div>
                <div style="border-left: 3px solid var(--sev-info); padding-left: 12px;">
                    <div style="color: var(--text-main); font-weight: 500; font-size: 13px;">Increase Event Log Retention</div>
                    <div style="color: var(--text-muted); font-size: 12px; margin-top: 4px;">Security event logs rolled over after 4 days. Recommend increasing size to 1GB or forwarding to SIEM.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

elif st.session_state.current_page == 'Timeline':
    # ==========================================
    # 4. INVESTIGATION TIMELINE PAGE
    # ==========================================
    st.markdown("""<div style="padding: 16px; background-color: var(--bg-main); border-radius: 8px;"><div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;"><h2 style="color: var(--text-secondary); font-size: 20px; font-weight: 500; margin: 0;">4. Investigation Timeline</h2><input type="text" placeholder="Search timeline..." style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 12px; border-radius: 4px; width: 250px; font-size: 12px;"></div><div style="display: flex; gap: 12px; margin-bottom: 16px;"><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 10px; border-radius: 4px; font-size: 11px;"><option>All Artifact Types</option></select><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 10px; border-radius: 4px; font-size: 11px;"><option>All Sources</option></select><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 10px; border-radius: 4px; font-size: 11px;"><option>All Hosts</option></select><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 10px; border-radius: 4px; font-size: 11px;"><option>24 May 2025 - 25 May 2025</option></select><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 6px 10px; border-radius: 4px; font-size: 11px;"><option>More Filters</option></select></div><table class="ev-table" style="font-size: 11px; width: 100%; text-align: left; border-collapse: collapse;"><thead style="color: var(--text-dim); border-bottom: 1px solid var(--border-color);"><tr><th style="width: 30px; padding: 6px;"></th><th style="width: 100px; padding: 6px;">Time</th><th style="padding: 6px;">Event</th><th style="width: 100px; padding: 6px;">Type</th><th style="width: 100px; padding: 6px;">Source</th><th style="width: 120px; padding: 6px;">Host</th><th style="width: 50px; padding: 6px;">Action</th></tr></thead><tbody><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:31:44 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">PowerShell executed with encoded command</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">Process</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Sysmon</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:32:01 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Registry key modified for persistence</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">Registry</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Sysmon</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--badge-low-bg); color: var(--badge-low-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:13:14 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Outbound connection to suspicious IP</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">Network</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Zeek</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--badge-med-bg); color: var(--badge-med-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:06:41 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Credential dumped from lsass.exe</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">Memory</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Volatility</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-orange-bg); color: var(--tag-orange-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:06:47 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">New executable created in Temp directory</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">File System</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Sysmon</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">10:06:32 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Possible file exfiltration attempt</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">Network</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Zeek</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">09:31:00 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Evidence parsing completed</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">System</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">ARGUS</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">09:57:32 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Evidence uploaded</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">System</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">ARGUS</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr><tr><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><div class="icon-box" style="background-color: var(--tag-purple-bg); color: var(--tag-purple-text); width: 20px; height: 20px; border-radius: 4px; display: flex; align-items: center; justify-content: center;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div></td><td style="padding: 6px; border-bottom: 1px solid var(--border-color); color: var(--text-muted);">09:15:00 AM</td><td style="color: var(--text-main); padding: 6px; border-bottom: 1px solid var(--border-color);">Case created</td><td style="padding: 6px; border-bottom: 1px solid var(--border-color);"><span style="color: var(--primary-main);">System</span></td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">ARGUS</td><td style="color: var(--text-muted); padding: 6px; border-bottom: 1px solid var(--border-color);">Workstation-01</td><td style="color: var(--primary-main); cursor: pointer; padding: 6px; border-bottom: 1px solid var(--border-color);">View</td></tr></tbody></table><div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; font-size: 11px; color: var(--text-dim);"><div>Showing 1 to 20 of 145 events</div><div style="display: flex; gap: 4px; align-items: center;"><span style="padding: 4px 8px; cursor: pointer;">&lt;</span><span style="background-color: var(--primary-main); color: white; padding: 4px 8px; border-radius: 4px; cursor: pointer;">1</span><span style="padding: 4px 8px; cursor: pointer;">2</span><span style="padding: 4px 8px; cursor: pointer;">3</span><span style="padding: 4px 8px;">...</span><span style="padding: 4px 8px; cursor: pointer;">8</span><span style="padding: 4px 8px; cursor: pointer;">&gt;</span><div style="margin-left: 12px;">Items per page:</div><select style="background-color: var(--border-color); border: 1px solid var(--border-light); color: var(--text-main); padding: 2px; border-radius: 4px; font-size: 11px;"><option>20 v</option></select></div></div></div>""", unsafe_allow_html=True)

elif st.session_state.current_page == 'AI':
    # ==========================================
    # 5. AI FINDINGS / ASSISTANT PAGE
    # ==========================================
    st.markdown("<h2 style='color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; margin-bottom: 24px; letter-spacing: -0.5px;'>5. AI Findings / Assistant</h2>", unsafe_allow_html=True)
    
    tab_f, tab_a = st.tabs(["AI Findings", "AI Assistant"])
    
    findings_html = """
    <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; height: 100%;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
    <div style="color: var(--text-main); font-size: 14px; font-weight: 600;">Top AI Findings (17)</div>
    <div style="color: var(--text-dim); cursor: pointer;">✕</div>
    </div>
    <div style="background-color: var(--hover-bg); border: 1px solid var(--border-color); border-left: 3px solid #ef4444; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Malicious PowerShell Execution</div><div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">HIGH</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 90%</div>
    </div>
    <div style="background-color: var(--bg-sidebar); border: 1px solid var(--border-color); border-left: 3px solid #ef4444; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Credential Dumping Activity</div><div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">HIGH</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 90%</div>
    </div>
    <div style="background-color: var(--bg-sidebar); border: 1px solid var(--border-color); border-left: 3px solid #ef4444; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Registry Run Key Persistence</div><div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">HIGH</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 75%</div>
    </div>
    <div style="background-color: var(--bg-sidebar); border: 1px solid var(--border-color); border-left: 3px solid #f59e0b; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Lateral Movement via RDP</div><div style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">MEDIUM</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 86%</div>
    </div>
    <div style="background-color: var(--bg-sidebar); border: 1px solid var(--border-color); border-left: 3px solid #f59e0b; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Outbound Connection to Suspicious IP</div><div style="background-color: var(--badge-med-bg); color: var(--badge-med-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">MEDIUM</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 78%</div>
    </div>
    <div style="background-color: var(--bg-sidebar); border: 1px solid var(--border-color); border-left: 3px solid #10b981; border-radius: 4px; padding: 12px; margin-bottom: 16px; cursor: pointer;">
    <div style="display: flex; justify-content: space-between;"><div style="color: var(--text-main); font-size: 12px; font-weight: 500;">Possible Data Exfiltration</div><div style="background-color: #064e3b; color: var(--badge-low-text); padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: bold;">LOW</div></div><div style="color: var(--text-dim); font-size: 11px; margin-top: 4px;">Confidence: 91%</div>
    </div>
    <div style="text-align: center; color: var(--primary-main); font-size: 12px; font-weight: 500; cursor: pointer;">View All Findings</div>
    </div>
    """
    
    with tab_f:
        c1, c2 = st.columns([4, 6])
        with c1:
            st.markdown(findings_html, unsafe_allow_html=True)
        with c2:
            st.markdown("""<div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; height: 100%;">
            <div style="color: var(--text-dim); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 16px;">Finding Details</div>
            <h3 style="color: var(--text-main); font-size: 18px; font-weight: 500; margin: 0 0 12px 0;">Suspicious PowerShell Execution</h3>
            <div style="display: flex; gap: 12px; margin-bottom: 20px;">
                <div style="background-color: var(--badge-high-bg); color: var(--badge-high-text); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">SEVERITY: HIGH</div>
                <div style="background-color: var(--border-color); color: var(--text-muted); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">CONFIDENCE: 90%</div>
            </div>
            <div style="color: var(--text-muted); font-size: 13px; line-height: 1.5; margin-bottom: 24px;">PowerShell executed an encoded command that may be malicious.</div>
<div style="color: var(--text-dim); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 8px;">Evidence Sources</div>
            <ul style="color: var(--text-muted); font-size: 13px; padding-left: 20px; margin-bottom: 24px; line-height: 1.6;">
                <li>Workstation-Memory.dmp</li>
                <li>Security.evtx</li>
            </ul>
<div style="color: var(--text-dim); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 8px;">MITRE ATT&CK</div>
            <div style="color: var(--text-muted); font-size: 13px; margin-bottom: 24px;">T1059.001 - PowerShell</div>
<div style="display: flex; gap: 40px;">
                <div>
                    <div style="color: var(--text-dim); font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">First Seen</div>
                    <div style="color: var(--text-muted); font-size: 13px;">25 May 2025 10:31 AM</div>
                </div>
                <div>
                    <div style="color: var(--text-dim); font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Last Seen</div>
                    <div style="color: var(--text-muted); font-size: 13px;">25 May 2025 10:31 AM</div>
                </div>
            </div>
            </div>""", unsafe_allow_html=True)
            
    with tab_a:
        c1, c2 = st.columns([4, 6])
        with c1:
            st.markdown(findings_html, unsafe_allow_html=True)
        with c2:
            st.markdown("""<div style="display: flex; flex-direction: column; height: 100%;">
            <div style="display: flex; justify-content: flex-end; margin-bottom: 16px;">
                <div style="background-color: var(--primary-dark); border-radius: 8px 8px 0 8px; padding: 12px 16px; color: #eff6ff; font-size: 13px; max-width: 80%;">
                    What was the initial access vector in this case?
                </div>
            </div>
<div style="display: flex; margin-bottom: 24px;">
                <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px 8px 8px 0; padding: 16px; color: var(--text-muted); font-size: 13px; max-width: 90%; line-height: 1.6;">
                    Based on the available evidence, the initial access vector appears to be via a phishing email that led to the execution of a malicious PowerShell script on the victim workstation.

            st.markdown("#### 💬 Ask Argus Forensic AI")
            user_query = st.text_input("Enter question about this case:", placeholder="e.g. What was the initial access vector in this case?", key="ai_chat_query_input")
            if user_query and st.button("Ask AI Agent", type="primary", key="btn_ask_ai"):
                with st.spinner("Querying Argus AI Agent & Sanitization Gateway..."):
                    ai_res = api_query_case("CASE-2025-0007", user_query)
                    st.markdown(f"**AI Response:**\n{ai_res.get('response')}")
                    if ai_res.get("injection_flagged"):
                        st.warning(f"⚠️ Prompt Injection Gate Flagged (Score: {ai_res.get('injection_score')})")

                    <br><br>
                    Evidence:
                    <ul style="padding-left: 20px; margin-top: 8px; margin-bottom: 16px;">
                        <li>Suspicious email with attachment found in Outlook mailbox (25 May 2025 08:12 AM)</li>
                        <li>PowerShell script executed from user Downloads folder (25 May 2025 09:15 AM)</li>
                        <li>Script downloaded additional payload from suspicious external IP</li>
                    </ul>
                    Confidence: 90%<br>
                    <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-top: 8px;">
                        <span style="color: var(--text-dim); font-size: 11px;">Sources: Outlook.msg, PowerShell.evtx, network.log</span>
                        <span style="color: var(--text-dimmer); font-size: 11px;">11:32 AM</span>
                    </div>
                </div>
            </div>
<div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
                <div style="background-color: transparent; border: 1px solid var(--primary-dark); color: var(--primary-main); border-radius: 16px; padding: 6px 12px; font-size: 11px; cursor: pointer;">Show me related timeline events</div>
                <div style="background-color: transparent; border: 1px solid var(--primary-dark); color: var(--primary-main); border-radius: 16px; padding: 6px 12px; font-size: 11px; cursor: pointer;">What data was accessed?</div>
                <div style="background-color: transparent; border: 1px solid var(--primary-dark); color: var(--primary-main); border-radius: 16px; padding: 6px 12px; font-size: 11px; cursor: pointer;">Any lateral movement?</div>
            </div>
<div style="margin-top: auto; position: relative;">
                <input type="text" placeholder="Ask a question about this case..." style="width: 100%; background-color: var(--bg-main); border: 1px solid var(--border-color); color: white; padding: 12px 40px 12px 16px; border-radius: 8px; font-size: 13px;">
                <div style="position: absolute; right: 8px; top: 8px; background-color: var(--primary-main); width: 26px; height: 26px; border-radius: 4px; display: flex; align-items: center; justify-content: center; cursor: pointer;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
                </div>
                <div style="color: var(--text-dimmer); font-size: 10px; margin-top: 8px; text-align: center;">AI responses are generated based on case evidence and may not be 100% accurate.</div>
            </div>
</div>""", unsafe_allow_html=True)


elif st.session_state.current_page == 'Notes':
    # ==========================================
    # 8. CASE NOTES PAGE
    # ==========================================
    
    top_c1, top_c2 = st.columns([8.5, 1.5], vertical_alignment="center")
    with top_c1:
        st.markdown("<h2 style='color: var(--text-secondary); font-size: 20px; font-weight: 500; margin: 0;'>8. Case Notes</h2>", unsafe_allow_html=True)
    with top_c2:
        st.button("+ New Note", type="primary", use_container_width=True)
    st.markdown('<hr style="margin-top: 8px; margin-bottom: 24px; border-color: var(--border-color);">', unsafe_allow_html=True)
    
    c1, c2 = st.columns([3.5, 6.5])
    with c1:
        st.markdown("""
<input type="text" placeholder="🔍 Search notes..." style="width: 100%; background-color: var(--bg-main); border: 1px solid var(--border-color); color: white; padding: 10px 12px; border-radius: 6px; font-size: 13px; margin-bottom: 16px;">
        <div style="background-color: var(--bg-card); border: 1px solid var(--primary-main); border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; display: flex; gap: 12px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background-color: var(--badge-med-bg); color: var(--badge-med-text); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <div style="flex-grow: 1;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                    <div style="color: var(--text-main); font-size: 13px; font-weight: 500;">Initial Investigation Notes</div>
                    <div style="color: var(--text-dimmer); font-size: 12px; cursor: pointer;">✕</div>
                </div>
                <div style="color: var(--text-dim); font-size: 11px; line-height: 1.4; margin-bottom: 8px;">Reviewed initial evidence and identified suspicious PowerShell activity.</div>
                <div style="display: flex; justify-content: space-between; align-items: center; color: var(--text-dimmer); font-size: 10px;">
                    <div>25 May 2025 10:05 AM</div>
                    <div>John Doe</div>
                </div>
            </div>
        </div>
<div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; display: flex; gap: 12px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background-color: var(--badge-high-bg); color: var(--badge-high-text); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <div style="flex-grow: 1;">
                <div style="color: var(--text-main); font-size: 13px; font-weight: 500; margin-bottom: 4px;">Credential Dumping Review</div>
                <div style="color: var(--text-dim); font-size: 11px; line-height: 1.4; margin-bottom: 8px;">Analyzed memory dump, possible credential dumping via lsass.exe.</div>
                <div style="display: flex; justify-content: space-between; align-items: center; color: var(--text-dimmer); font-size: 10px;">
                    <div>25 May 2025 10:42 AM</div>
                    <div>John Doe</div>
                </div>
            </div>
        </div>
<div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; display: flex; gap: 12px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background-color: var(--badge-low-bg); color: var(--badge-low-text); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <div style="flex-grow: 1;">
                <div style="color: var(--text-main); font-size: 13px; font-weight: 500; margin-bottom: 4px;">Network Analysis</div>
                <div style="color: var(--text-dim); font-size: 11px; line-height: 1.4; margin-bottom: 8px;">Outbound connections to suspicious IP identified.</div>
                <div style="display: flex; justify-content: space-between; align-items: center; color: var(--text-dimmer); font-size: 10px;">
                    <div>25 May 2025 11:02 AM</div>
                    <div>John Doe</div>
                </div>
            </div>
        </div>
<div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; display: flex; gap: 12px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background-color: var(--tag-purple-bg); color: var(--tag-purple-text); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <div style="flex-grow: 1;">
                <div style="color: var(--text-main); font-size: 13px; font-weight: 500; margin-bottom: 4px;">RDP Connection Review</div>
                <div style="color: var(--text-dim); font-size: 11px; line-height: 1.4; margin-bottom: 8px;">Confirmed RDP connection to remote host at 09:58 AM.</div>
                <div style="display: flex; justify-content: space-between; align-items: center; color: var(--text-dimmer); font-size: 10px;">
                    <div>25 May 2025 11:30 AM</div>
                    <div>John Doe</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with c2:
        st.markdown("""
        <div style="margin-top: -48px;"></div>
<div style="background-color: var(--bg-main); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; min-height: 400px; display: flex; flex-direction: column;">
            <div style="color: var(--text-main); font-size: 12px; font-weight: 600; margin-bottom: 12px;">Note Details</div>
<div style="color: var(--text-dim); font-size: 11px; margin-bottom: 4px;">Title</div>
<div style="color: var(--text-main); font-size: 14px; font-weight: 500; margin-bottom: 20px;">Initial Investigation Notes</div>
<div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; flex-grow: 1;">
                <!-- Formatting Toolbar -->
                <div style="display: flex; gap: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; margin-bottom: 16px; color: var(--text-dim);">
                    <div style="display: flex; gap: 12px;">
                        <span style="font-weight: bold; cursor: pointer;">B</span>
                        <span style="font-style: italic; font-family: serif; cursor: pointer;">I</span>
                        <span style="text-decoration: underline; cursor: pointer;">U</span>
                    </div>
                    <div style="width: 1px; background-color: var(--border-color);"></div>
                    <div style="display: flex; gap: 12px;">
                        <span style="cursor: pointer;">≡</span>
                        <span style="cursor: pointer;">=</span>
                        <span style="cursor: pointer;">-</span>
                    </div>
                    <div style="width: 1px; background-color: var(--border-color);"></div>
                    <div style="display: flex; gap: 12px;">
                        <span style="cursor: pointer;">&lt;&gt;</span>
                        <span style="cursor: pointer;">👁</span>
                    </div>
                </div>
<div style="color: var(--text-muted); font-size: 13px; line-height: 1.6;">
                    Reviewed initial evidence including memory dump,
                    event logs and network captures.<br><br>
                    Found evidence of malicious PowerShell execution
                    and possible credential dumping.<br><br>
                    Next steps:<br>
                    <ul style="padding-left: 20px; margin-top: 4px;">
                        <li>Deep dive into memory artifacts</li>
                        <li>Analyze registry changes</li>
                        <li>Correlate network activity</li>
                    </ul>
                </div>
            </div>
<div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
                <div style="color: var(--text-dimmer); font-size: 11px;">Last updated: 25 May 2025 10:05 AM</div>
                <!-- Native Streamlit buttons shouldn't be placed inside HTML, we will close this and add them below natively -->
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Native buttons for Case Notes right panel
        b_c1, b_c2, b_c3 = st.columns([6, 2, 2])
        with b_c2:
            st.button("Cancel", use_container_width=True)
        with b_c3:
            st.button("Update Note", type="primary", use_container_width=True)

elif st.session_state.current_page == 'Report':
    # ==========================================
    # 7. REPORT BUILDER PAGE
    # ==========================================
    st.markdown('<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;"><h2 style="color: var(--text-secondary); font-size: 24px; font-weight: 600; margin: 0; letter-spacing: -0.5px;">7. Report Builder</h2><div style="display: flex; gap: 32px;"><div style="display: flex; align-items: center; gap: 8px; color: var(--text-main); font-size: 13px; font-weight: 500;"><div style="background-color: var(--primary-main); width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white;">1</div> Select Content</div><div style="display: flex; align-items: center; gap: 8px; color: var(--text-dim); font-size: 13px;"><div style="background-color: var(--border-color); width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center;">2</div> Preview</div><div style="display: flex; align-items: center; gap: 8px; color: var(--text-dim); font-size: 13px;"><div style="background-color: var(--border-color); width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center;">3</div> Export &amp; Submit</div></div></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([3, 5, 3])
    
    with col1:
        st.markdown('<div style="color: var(--text-main); font-size: 13px; font-weight: 600; margin-bottom: 16px;">Select Content</div>', unsafe_allow_html=True)
        
        c1a, c1b = st.columns([6, 4])
        with c1a: sel_timeline = st.checkbox("Timeline Events", value=True)
        with c1b: st.markdown('<div style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); padding: 2px 6px; border-radius: 4px; font-size: 10px; text-align: center; margin-top: 4px;">12 selected</div>', unsafe_allow_html=True)
        
        c2a, c2b = st.columns([6, 4])
        with c2a: sel_ai = st.checkbox("AI Findings", value=True)
        with c2b: st.markdown('<div style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); padding: 2px 6px; border-radius: 4px; font-size: 10px; text-align: center; margin-top: 4px;">6 selected</div>', unsafe_allow_html=True)
        
        c3a, c3b = st.columns([6, 4])
        with c3a: sel_visuals = st.checkbox("Screenshots & Visuals", value=True)
        with c3b: st.markdown('<div style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); padding: 2px 6px; border-radius: 4px; font-size: 10px; text-align: center; margin-top: 4px;">5 selected</div>', unsafe_allow_html=True)
        
        c4a, c4b = st.columns([6, 4])
        with c4a: sel_notes = st.checkbox("Notes", value=True)
        with c4b: st.markdown('<div style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); padding: 2px 6px; border-radius: 4px; font-size: 10px; text-align: center; margin-top: 4px;">8 selected</div>', unsafe_allow_html=True)
        
        c5a, c5b = st.columns([6, 4])
        with c5a: sel_evidence = st.checkbox("Evidence Summary", value=True)
        with c5b: st.markdown('<div style="background-color: rgba(59, 130, 246, 0.2); color: var(--primary-light); padding: 2px 6px; border-radius: 4px; font-size: 10px; text-align: center; margin-top: 4px;">1 selected</div>', unsafe_allow_html=True)
        
    with col3:
        st.markdown('<div style="color: var(--text-main); font-size: 13px; font-weight: 600; margin-bottom: 16px;">Report Details</div>', unsafe_allow_html=True)
        
        rep_title = st.text_input("Report Title", value="Corporate Workstation Compromise")
        rep_type = st.selectbox("Report Type", options=["Investigation Report", "Executive Summary", "Technical Evidence Report"])
        
        st.markdown('<div style="color: var(--text-secondary); font-size: 12px; margin-top: 16px; margin-bottom: 8px; font-weight: 500;">Include Sections</div>', unsafe_allow_html=True)
        
        inc_exec = st.checkbox("Executive Summary", value=True, key="inc_exec")
        inc_timeline = st.checkbox("Timeline of Events", value=sel_timeline, key="inc_timeline")
        inc_ai = st.checkbox("AI Findings Summary", value=sel_ai, key="inc_ai")
        inc_evid = st.checkbox("Evidence Summary", value=sel_evidence, key="inc_evid")
        inc_conc = st.checkbox("Conclusion", value=True, key="inc_conc")
        
        st.markdown('<div style="color: var(--text-secondary); font-size: 12px; margin-top: 16px; margin-bottom: 8px; font-weight: 500;">Format</div>', unsafe_allow_html=True)
        st.selectbox("Format", options=["PDF", "DOCX", "HTML"], label_visibility="collapsed")
        
        st.write("")
        b1, b2 = st.columns(2)
        with b1: st.button("Save Draft", use_container_width=True)
        with b2: st.button("Preview Report", type="primary", use_container_width=True)

        st.markdown("### 📥 Legal Report Download")
        case_to_export = st.text_input("Report Case ID", value="CASE-2025-0007", key="report_case_id_input")
        r_col1, r_col2 = st.columns(2)
        with r_col1:
            if st.button("Fetch HTML Report", type="primary", key="btn_fetch_html_report"):
                content, content_type = api_get_report(case_to_export, fmt="html")
                if content:
                    st.download_button("Download HTML Report", data=content, file_name=f"{case_to_export}_report.html", mime="text/html", key="dl_html_report_btn")
                else:
                    st.error("Report generation failed or case has no findings.")
        with r_col2:
            if st.button("Fetch JSON Report", type="secondary", key="btn_fetch_json_report"):
                content, content_type = api_get_report(case_to_export, fmt="json")
                if content:
                    st.download_button("Download JSON Report", data=content, file_name=f"{case_to_export}_report.json", mime="application/json", key="dl_json_report_btn")
                else:
                    st.error("Report generation failed or case has no findings.")

        
    with col2:
        toc_items = []
        if inc_exec: toc_items.append("Executive Summary")
        if inc_timeline: toc_items.append("Timeline of Events")
        if inc_ai: toc_items.append("AI Findings Summary")
        if inc_evid: toc_items.append("Evidence Summary")
        if inc_conc: toc_items.append("Conclusion")
        
        toc_html = ""
        for idx, item in enumerate(toc_items, 1):
            toc_html += f'<div style="display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 12px; color: var(--border-light);"><div>{idx}. {item}</div><div style="border-bottom: 1px dotted var(--text-muted); flex-grow: 1; margin: 0 12px; position: relative; top: -6px;"></div><div>{idx * 2 + 1}</div></div>'
            
        preview_html = f'<div style="background-color: #ffffff; color: var(--bg-sidebar); border-radius: 4px; padding: 40px; box-shadow: 0 4px 6px -1px var(--shadow-1); min-height: 550px; display: flex; flex-direction: column;"><div style="text-align: center; margin-bottom: 32px;"><div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 16px;"><div style="background-color: var(--primary-dark); color: white; width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center;"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><circle cx="12" cy="11" r="3"></circle></svg></div><div style="text-align: left;"><div style="color: var(--primary-dark); font-size: 24px; font-weight: bold; letter-spacing: 1px; line-height: 1;">ARGUS</div><div style="color: var(--text-dimmer); font-size: 10px; font-weight: 600; letter-spacing: 1px;">DIGITAL FORENSICS</div></div></div><div style="font-size: 12px; font-weight: bold; letter-spacing: 0.5px;">{rep_type.upper()} (DRAFT)</div></div><div style="margin-bottom: 32px; font-size: 12px; display: flex; flex-direction: column; gap: 8px;"><div><span style="color: var(--text-dimmer); width: 100px; display: inline-block;">Case ID:</span> <strong>CASE-2025-0007</strong></div><div><span style="color: var(--text-dimmer); width: 100px; display: inline-block;">Case Title:</span> <strong>{rep_title}</strong></div><div><span style="color: var(--text-dimmer); width: 100px; display: inline-block;">Investigator:</span> <strong>John Doe (Analyst)</strong></div><div><span style="color: var(--text-dimmer); width: 100px; display: inline-block;">Date:</span> <strong>25 May 2025</strong></div></div><div style="font-size: 13px; font-weight: bold; margin-bottom: 16px; border-bottom: 2px solid var(--text-secondary); padding-bottom: 8px;">Table of Contents</div><div style="flex-grow: 1;">{toc_html}</div><div style="text-align: center; color: var(--text-dim); font-size: 11px; margin-top: 24px;">Page 1 of 12</div></div>'
        
        st.markdown(preview_html, unsafe_allow_html=True)
