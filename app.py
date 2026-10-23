from pathlib import Path

import streamlit as st

from data import load_demo_findings
from views.dashboard import render_dashboard
from views.new_scan import render_new_scan
from views.findings import render_findings
from views.fix_assistant import render_fix_assistant
from views.verification import render_verification
from views.export_report import render_export_report


# =====================================================
# 1. PROJECT PATHS
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "assets" / "vulfin.png"


# =====================================================
# 2. PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="VulFin | AI Security Reviewer",
    page_icon=str(LOGO_PATH) if LOGO_PATH.is_file() else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =====================================================
# 3. GLOBAL STYLING
# =====================================================

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1450px;
        padding-top: 1.3rem;
        padding-bottom: 3rem;
    }

    [data-testid="stSidebar"] {
        background: #0B111B;
        border-right: 1px solid #243044;
    }

    [data-testid="stSidebar"] .block-container {
        padding-top: 1.2rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    .vf-brand-label {
        color: #F4F7FB;
        font-size: 1.55rem;
        font-weight: 800;
        margin: 0;
    }

    .vf-brand-caption {
        color: #8FA2B9;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.11rem;
        margin-top: 3px;
    }

    .vf-section-label {
        color: #8294AA;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.13rem;
        margin: 0.8rem 0 0.5rem 0;
    }

    .vf-muted {
        color: #A7B6C8;
        font-size: 0.91rem;
    }

    .vf-eyebrow {
        color: #57E3C0;
        font-size: 0.74rem;
        font-weight: 700;
        letter-spacing: 0.12rem;
        text-transform: uppercase;
    }

    .vf-side-note {
        color: #91A1B5;
        font-size: 0.78rem;
        line-height: 1.5;
    }

    [data-testid="stMetric"] {
        background: #161B26;
        border: 1px solid #293447;
        border-radius: 12px;
        padding: 15px;
    }

    [data-testid="stSidebar"] div.stButton > button {
        width: 100%;
        min-height: 43px;
        text-align: left;
        justify-content: flex-start;
        border-radius: 10px;
        padding: 0.55rem 0.8rem;
        font-size: 0.9rem;
        font-weight: 600;
    }

    [data-testid="stSidebar"]
    div.stButton > button[kind="secondary"] {
        background: transparent;
        color: #B7C4D6;
        border: 1px solid transparent;
    }

    [data-testid="stSidebar"]
    div.stButton > button[kind="secondary"]:hover {
        background: #182438;
        color: #FFFFFF;
        border: 1px solid #2B3A50;
    }

    [data-testid="stSidebar"]
    div.stButton > button[kind="primary"] {
        background: #57E3C0;
        color: #071711;
        border: 1px solid #57E3C0;
        font-weight: 750;
    }

    [data-testid="stSidebar"] hr {
        border-color: #243044;
        margin: 1rem 0;
    }

    div.stButton > button {
        border-radius: 9px;
        font-weight: 600;
        min-height: 2.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =====================================================
# 4. SHARED SESSION STATE
# =====================================================

DEFAULTS = {
    "findings": [],
    "demo_mode": False,
    "project_name": "",
    "scan_status": "Not scanned",
    "active_page": "Dashboard",
    "last_real_findings": [],
    "verification_results": None,
    "has_real_scan": False,
    "scan_id": None,
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# =====================================================
# 5. SIDEBAR NAVIGATION
# =====================================================

NAV_ITEMS = [
    ("Dashboard", "▦"),
    ("New Scan", "＋"),
    ("Findings", "⚑"),
    ("Fix Assistant", "✦"),
    ("Verification", "↻"),
    ("Export Report", "⇩"),
]

with st.sidebar:

    # Use the complete image at a fixed width.
    # No cropping CSS or fixed image height is applied.
    if LOGO_PATH.is_file():
        st.image(
            str(LOGO_PATH),
            width=210,
            caption=None,
            output_format="PNG",
        )
    else:
        st.error("VulFin logo could not be found.")
        st.code(str(LOGO_PATH))

    st.markdown(
        '<p class="vf-brand-label">VulFin</p>'
        '<p class="vf-brand-caption">SECURITY WORKSPACE</p>',
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown(
        '<div class="vf-section-label">MAIN MENU</div>',
        unsafe_allow_html=True,
    )

    for label, symbol in NAV_ITEMS:

        is_active = st.session_state.active_page == label

        if st.button(
            f"{symbol}   {label}",
            key=f"nav_{label.lower().replace(' ', '_')}",
            use_container_width=True,
            type="primary" if is_active else "secondary",
        ):
            st.session_state.active_page = label
            st.rerun()

    st.divider()

    st.markdown(
        '<div class="vf-section-label">DEVELOPMENT TOOLS</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<p class="vf-side-note">'
        'Explore the interface using sample security findings.'
        '</p>',
        unsafe_allow_html=True,
    )

    if st.button(
        "＋   Load demo findings",
        key="sidebar_load_demo",
        use_container_width=True,
    ):
        load_demo_findings()
        st.session_state.verification_results = None
        st.session_state.active_page = "Dashboard"
        st.rerun()

    if st.button(
        "↺   Clear results",
        key="sidebar_clear_results",
        use_container_width=True,
    ):
        st.session_state.findings = []
        st.session_state.demo_mode = False
        st.session_state.project_name = ""
        st.session_state.scan_status = "Not scanned"
        st.session_state.last_real_findings = []
        st.session_state.verification_results = None
        st.session_state.has_real_scan = False
        st.session_state.scan_id = None
        st.session_state.active_page = "Dashboard"
        st.rerun()

    st.divider()

    st.markdown(
        '<p class="vf-side-note">'
        '<span style="color:#57E3C0;">●</span> '
        'Frontend prototype<br>CY-02 · VulFin'
        '</p>',
        unsafe_allow_html=True,
    )


# =====================================================
# 6. MAIN HEADER
# =====================================================

# Give the logo enough horizontal space so it is not
# squeezed into a narrow column.
logo_col, brand_col = st.columns(
    [2, 5],
    vertical_alignment="center",
)

with logo_col:

    if LOGO_PATH.is_file():
        st.image(
            str(LOGO_PATH),
            width=245,
            caption=None,
            output_format="PNG",
        )
    else:
        st.error("VulFin logo is missing.")
        st.caption(str(LOGO_PATH))

with brand_col:

    st.markdown(
        '<p class="vf-eyebrow">VULFIN SECURITY WORKSPACE</p>',
        unsafe_allow_html=True,
    )

    st.markdown("## VulFin")

    st.markdown(
        '<p class="vf-muted">'
        'AI Security Reviewer for AI-generated websites'
        '</p>',
        unsafe_allow_html=True,
    )

st.divider()


# =====================================================
# 7. DEMO-MODE INDICATOR
# =====================================================

if st.session_state.demo_mode:
    st.warning(
        "DEMO MODE — these findings are illustrative examples. "
        "They are not results from scanning your uploaded source code."
    )


# =====================================================
# 8. PAGE ROUTER
# =====================================================

page = st.session_state.active_page

if page == "Dashboard":
    render_dashboard()

elif page == "New Scan":
    render_new_scan()

elif page == "Findings":
    render_findings()

elif page == "Fix Assistant":
    render_fix_assistant()

elif page == "Verification":
    render_verification()

elif page == "Export Report":
    render_export_report()

else:
    st.error("Unknown page. Select a page from the sidebar.")