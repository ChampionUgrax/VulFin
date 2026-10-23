
from pathlib import Path
from copy import deepcopy
import base64

import streamlit as st

from views.dashboard import render_dashboard
from views.new_scan import render_new_scan
from views.findings import render_findings
from views.fix_assistant import render_fix_assistant
from views.verification import render_verification
from views.export_report import render_export_report


# ======================================================
# CONFIGURATION
# ======================================================

BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "assets" / "vulfin.png"

st.set_page_config(
    page_title="VulFin | AI Security Assistant",
    page_icon=str(LOGO_PATH) if LOGO_PATH.exists() else "🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ======================================================
# SESSION STATE
# ======================================================

DEFAULT_STATE = {
    "active_page": "Dashboard",
    "findings": [],
    "demo_mode": False,
    "project_name": "",
    "scan_status": "Not scanned",
    "scan_id": None,
    "scan_timestamp": None,
    "files_scanned": 0,
    "scan_summary": {},
    "scan_errors": [],
    "last_scan_snapshot": None,
    "previous_scan_snapshot": None,
    "verification_results": None,
    "has_real_scan": False,
    "last_real_findings": [],
    "selected_finding_id": None,
    "last_generated_prompt": None,
    "last_prompt_finding_id": None,
    "last_prompt_style": None,
    "review_status": {},
    "latest_scan_attempt_status": None,
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = deepcopy(value)


# ======================================================
# NAVIGATION
# ======================================================

PAGES = {
    "Dashboard": render_dashboard,
    "New Scan": render_new_scan,
    "Findings": render_findings,
    "Fix Assistant": render_fix_assistant,
    "Verification": render_verification,
    "Export Report": render_export_report,
}

if st.session_state.active_page not in PAGES:
    st.session_state.active_page = "Dashboard"


# ======================================================
# STYLING
# ======================================================

st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background: #0D1117;
    }

    .block-container {
        max-width: 1450px;
        padding-top: 1.6rem;
        padding-left: 1.5rem;
        padding-right: 1.5rem;
        padding-bottom: 2rem;
    }

    [data-testid="stSidebar"],
    [data-testid="stSidebarCollapsedControl"],
    [data-testid="collapsedControl"] {
        display: none !important;
    }

    .vf-brand {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        padding: 12px 0 14px;
        width: 100%;
    }

    .vf-logo {
        width: 72px;
        height: auto;
        max-height: 72px;
        object-fit: contain;
    }

    .vf-name {
        font-size: 32px;
        line-height: 1.2;
        font-weight: 800;
        color: #F4F7FB;
        margin: 0;
    }

    .st-key-vf_navigation [data-testid="stHorizontalBlock"] {
        display: flex;
        flex-wrap: nowrap;
        gap: 8px;
    }

    .st-key-vf_navigation [data-testid="column"] {
        min-width: 0 !important;
    }

    .st-key-vf_navigation div.stButton > button {
        width: 100%;
        min-height: 43px;
        border-radius: 9px;
        font-size: 14px;
        font-weight: 650;
    }

    .st-key-vf_navigation
    div.stButton > button[kind="primary"] {
        background: #57E3C0;
        color: #071711;
        border: 1px solid #57E3C0;
    }

    .st-key-vf_navigation
    div.stButton > button[kind="secondary"] {
        background: #161B26;
        color: #D0D9E5;
        border: 1px solid #293447;
    }

    .st-key-vf_navigation
    div.stButton > button[kind="secondary"]:hover {
        border-color: #57E3C0;
        color: white;
    }

    @media (max-width: 900px) {
        .st-key-vf_navigation [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap !important;
        }

        .st-key-vf_navigation [data-testid="column"] {
            flex: 1 1 29% !important;
            width: 29% !important;
            max-width: none !important;
        }
    }

    @media (max-width: 560px) {
        .block-container {
            padding-top: 1rem;
            padding-left: .7rem;
            padding-right: .7rem;
        }

        .vf-logo {
            width: 55px;
            max-height: 55px;
        }

        .vf-name {
            font-size: 25px;
        }

        .st-key-vf_navigation [data-testid="column"] {
            flex: 1 1 44% !important;
            width: 44% !important;
            max-width: none !important;
        }

        .st-key-vf_navigation div.stButton > button {
            font-size: 12px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ======================================================
# CENTERED LOGO + NAME
# ======================================================

logo_html = ""

if LOGO_PATH.is_file():
    logo_base64 = base64.b64encode(
        LOGO_PATH.read_bytes()
    ).decode("utf-8")

    logo_html = (
        f'<img class="vf-logo" '
        f'src="data:image/png;base64,{logo_base64}" '
        f'alt="VulFin logo">'
    )

st.markdown(
    f"""
    <div class="vf-brand">
        {logo_html}
        <h1 class="vf-name">VulFin</h1>
    </div>
    """,
    unsafe_allow_html=True,
)


# ======================================================
# SIX PAGE NAVIGATION
# ======================================================

with st.container(key="vf_navigation"):
    columns = st.columns(6, gap="small")

    for column, page_name in zip(columns, PAGES):
        with column:
            selected = (
                st.session_state.active_page == page_name
            )

            if st.button(
                page_name,
                key=f"nav_{page_name.lower().replace(' ', '_')}",
                type="primary" if selected else "secondary",
                use_container_width=True,
            ):
                st.session_state.active_page = page_name
                st.rerun()

st.divider()


# ======================================================
# RENDER SELECTED PAGE
# ======================================================

PAGES[st.session_state.active_page]()
