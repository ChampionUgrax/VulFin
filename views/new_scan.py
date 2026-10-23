import streamlit as st

from data import load_demo_findings
from services.vulfin_service import (
    run_security_scan,
    compare_scan_results,
    BackendNotReadyError,
)


def render_new_scan():

    st.title("New security scan")
    st.caption(
        "Upload an authorised website source archive to start scanning."
    )

    uploaded_zip = st.file_uploader(
        "Upload website source code as a ZIP",
        type=["zip"],
        help="Only upload code you own or are authorised to review.",
        key="source_zip",
    )

    if uploaded_zip is not None:
        col1, col2 = st.columns(2)

        col1.metric(
            "Selected file",
            uploaded_zip.name,
        )

        col2.metric(
            "File size",
            f"{uploaded_zip.size / 1024:.1f} KB",
        )

    st.markdown("### Run security scan")

    if st.button(
        "Run security scan",
        type="primary",
        use_container_width=True,
        disabled=uploaded_zip is None,
    ):

        try:
            with st.spinner("Scanning website source code..."):

                result = run_security_scan(
                    uploaded_zip.getvalue(),
                    uploaded_zip.name,
                )

            new_findings = result["findings"]

            # Compare only against an earlier successful real scan.
            if st.session_state.has_real_scan:
                old_findings = st.session_state.last_real_findings

                comparison = compare_scan_results(
                    old_findings,
                    new_findings,
                )

                st.session_state.verification_results = comparison

            else:
                st.session_state.verification_results = None

            # Save the new real scan as the comparison baseline.
            st.session_state.last_real_findings = [
                item.copy() for item in new_findings
            ]

            st.session_state.has_real_scan = True
            st.session_state.findings = [
                item.copy() for item in new_findings
            ]

            st.session_state.demo_mode = False
            st.session_state.project_name = uploaded_zip.name
            st.session_state.scan_status = "Scan completed"
            st.session_state.scan_id = result.get("scan_id")
            st.session_state.active_page = "Findings"

            st.rerun()

        except BackendNotReadyError as exc:
            st.warning(
                f"{exc} The uploaded file was not scanned. "
                "Use the demo preview below while backend work continues."
            )

        except Exception as exc:
            st.session_state.scan_status = "Scan failed"
            st.error(f"Scan failed: {exc}")

    st.divider()

    st.markdown("### Preview the frontend")

    st.write(
        "Use demonstration findings to test the interface independently "
        "of the scanner backend."
    )

    if st.button(
        "Load demo findings",
        use_container_width=True,
    ):
        project_name = (
            uploaded_zip.name
            if uploaded_zip is not None
            else "Sample vulnerable website"
        )

        load_demo_findings(project_name)
        st.session_state.verification_results = None
        st.session_state.active_page = "Dashboard"
        st.rerun()

    st.caption(
        "Demo mode does not extract or scan the uploaded ZIP. "
        "These findings are illustrative examples."
    )

    with st.expander("How the scan will work after integration"):
        st.markdown(
            """
            1. Validate the uploaded archive and safely extract its contents.
            2. Run the approved source-code security scanners.
            3. Convert scanner output into a shared findings format.
            4. Show evidence, severity and remediation guidance.
            5. Rescan corrected code and compare results.
            """
        )