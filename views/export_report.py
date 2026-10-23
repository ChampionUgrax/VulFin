import json
import streamlit as st


def render_export_report():
    findings = st.session_state.findings

    st.title("Export Report")
    st.caption("Download the findings currently loaded in VulFin.")

    if not findings:
        st.info("Load findings before exporting a report.")
        return

    report = {
        "product": "VulFin",
        "project": st.session_state.project_name,
        "mode": "demo" if st.session_state.demo_mode else "scan",
        "scan_status": st.session_state.scan_status,
        "findings": findings,
    }

    st.markdown("### Report summary")
    st.write(f"**Project:** {report['project']}")
    st.write(f"**Finding count:** {len(findings)}")
    st.write(f"**Data mode:** {report['mode']}")

    st.download_button(
        "Download JSON report",
        data=json.dumps(report, indent=2),
        file_name="vulfin-security-report.json",
        mime="application/json",
        type="primary",
        use_container_width=True,
    )

    st.caption(
        "Demo exports contain illustrative findings. "
        "Actual scan reports will be available after backend integration."
    )