import streamlit as st


MOCK_FINDINGS = [
    {
        "id": "F-001",
        "fingerprint": "secret:src/config.js:api-key",
        "title": "Hardcoded API credential",
        "severity": "high",
        "category": "exposed_secret",
        "file": "src/config.js",
        "line": 18,
        "evidence": 'apiKey = "sk-••••••••"',
        "recommendation": (
            "Rotate the credential, remove it from source code, "
            "and use appropriate secret configuration."
        ),
        "explanation": (
            "Credentials committed in source code may be exposed "
            "to people who can access that code."
        ),
        "status": "open",
    },
    {
        "id": "F-002",
        "fingerprint": "access:src/routes/profile.py:check",
        "title": "Potential missing access check",
        "severity": "high",
        "category": "access_control",
        "file": "src/routes/profile.py",
        "line": 42,
        "evidence": "Example protected-route pattern requires review",
        "recommendation": (
            "Verify that the server authenticates the user and "
            "checks permission to access the requested resource."
        ),
        "explanation": (
            "Missing server-side authorisation can let a user "
            "access data or operations they should not be allowed to use."
        ),
        "status": "open",
    },
    {
        "id": "F-003",
        "fingerprint": "input:src/components/Comment.jsx:render",
        "title": "Potential unsafe HTML handling",
        "severity": "medium",
        "category": "unsafe_input",
        "file": "src/components/Comment.jsx",
        "line": 27,
        "evidence": "Example user-input rendering pattern requires review",
        "recommendation": (
            "Review how untrusted input reaches the browser. "
            "Use safe rendering or appropriate output encoding."
        ),
        "explanation": (
            "Unsafe rendering may create cross-site scripting risks, "
            "depending on how the user input is used."
        ),
        "status": "open",
    },
]


MOCK_VERIFICATION = [
    {
        "issue": "Hardcoded API credential",
        "status": "No longer detected",
        "severity": "high",
    },
    {
        "issue": "Potential missing access check",
        "status": "Still detected",
        "severity": "high",
    },
    {
        "issue": "Potential unsafe HTML handling",
        "status": "Newly detected",
        "severity": "medium",
    },
]


def load_demo_findings(project_name="Sample website"):
    """Load illustrative data for frontend testing."""
    st.session_state.findings = [
        item.copy() for item in MOCK_FINDINGS
    ]
    st.session_state.demo_mode = True
    st.session_state.project_name = project_name
    st.session_state.scan_status = "Demo results loaded"


def count_severity(findings, severity):
    """Count findings by severity."""
    return sum(
        1
        for item in findings
        if item.get("severity", "").lower() == severity
    )


def make_repair_prompt(finding):
    """Temporary prompt template until remediation.py is integrated."""
    return f"""
Review this security finding in my website source code.

Issue: {finding["title"]}
Severity: {finding["severity"]}
Category: {finding["category"]}
File: {finding["file"]}
Line: {finding.get("line") or "Not available"}
Evidence: {finding["evidence"]}

Recommended direction:
{finding["recommendation"]}

Propose the smallest safe code change.
Explain the change and the tests required.
Do not invent credentials or expose hidden secrets.
Do not claim the issue is fixed without a successful rescan.
""".strip()

def initialise_session_state():
    """Initialise shared state used by VulFin's pages and workflows."""
    defaults = {
        "findings": [],
        "demo_mode": False,
        "project_name": "",
        "scan_status": "Not scanned",
        "active_page": "Dashboard",
        "last_real_findings": [],
        "verification_results": None,
        "has_real_scan": False,
        "scan_id": None,
        "scan_files_scanned": None,
        "scan_timestamp": None,
        "selected_finding_id": None,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def clear_results():
    """Clear scan results and metadata without resetting navigation widgets."""
    st.session_state.findings = []
    st.session_state.demo_mode = False
    st.session_state.project_name = ""
    st.session_state.scan_status = "Not scanned"
    st.session_state.last_real_findings = []
    st.session_state.verification_results = None
    st.session_state.has_real_scan = False
    st.session_state.scan_id = None
    st.session_state.scan_files_scanned = None
    st.session_state.scan_timestamp = None
    st.session_state.selected_finding_id = None
