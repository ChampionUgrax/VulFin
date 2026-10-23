
import copy

import streamlit as st

from services import vulfin_service


def render_new_scan():

    # ==================================================
    # 1. PAGE HEADER
    # ==================================================

    st.title("New Security Scan")

    st.caption(
        "Upload your original website project as a ZIP "
        "file to identify potential security vulnerabilities."
    )

    # ==================================================
    # 2. UPLOAD ORIGINAL PROJECT
    # ==================================================

    st.subheader("1. Upload Project")

    uploaded_file = st.file_uploader(
        "Upload Original Project ZIP",
        type=["zip"],
        key="source_zip",
        help=(
            "Upload the original source code of your "
            "website as a ZIP archive."
        ),
    )

    if uploaded_file is not None:

        st.success(
            f"Selected project: {uploaded_file.name}"
        )

        file_size_mb = (
            uploaded_file.size / (1024 * 1024)
        )

        st.caption(
            f"File size: {file_size_mb:.2f} MB"
        )

    # ==================================================
    # 3. RUN INITIAL SECURITY SCAN
    # ==================================================

    st.subheader("2. Run Security Scan")

    st.write(
        "VulFin will analyse the uploaded source code "
        "and identify potential security vulnerabilities."
    )

    run_clicked = st.button(
        "Run Security Scan",
        key="start_security_scan",
        type="primary",
        use_container_width=True,
        disabled=uploaded_file is None,
    )

    if run_clicked:

        st.session_state.latest_scan_attempt_status = (
            "running"
        )

        try:

            # ==========================================
            # 4. EXECUTE SECURITY SCANNER
            # ==========================================

            with st.spinner(
                "Scanning project for vulnerabilities..."
            ):

                result = (
                    vulfin_service.run_security_scan(
                        uploaded_file.getvalue(),
                        uploaded_file.name,
                    )
                )

            # ==========================================
            # 5. VALIDATE SCANNER RESPONSE
            # ==========================================

            if not isinstance(result, dict):

                raise ValueError(
                    "Scanner returned an invalid response. "
                    "Expected a dictionary."
                )

            scan_status = str(
                result.get("status", "completed")
            ).lower()

            if scan_status not in {
                "completed",
                "complete",
                "success",
                "succeeded",
            }:

                raise ValueError(
                    "The security scan did not complete "
                    f"successfully. Status: {scan_status}"
                )

            findings = result.get(
                "findings",
                [],
            )

            if not isinstance(findings, list):

                raise ValueError(
                    "Scanner findings must be a list."
                )

            if not all(
                isinstance(finding, dict)
                for finding in findings
            ):

                raise ValueError(
                    "Each scanner finding must be "
                    "a dictionary."
                )

            # ==========================================
            # 6. EXTRACT SCAN INFORMATION
            # ==========================================

            project_name = result.get(
                "project_name",
                uploaded_file.name,
            )

            scan_id = result.get(
                "scan_id"
            )

            scanned_at = result.get(
                "scanned_at"
            )

            files_scanned = result.get(
                "files_scanned",
                0,
            )

            summary = result.get(
                "summary",
                {},
            )

            errors = result.get(
                "errors",
                [],
            )

            # ==========================================
            # 7. SAVE ORIGINAL SCAN BASELINE
            # ==========================================

            # This snapshot is used by the Verification
            # page when the user uploads a corrected ZIP.
            #
            # It must remain unchanged during the
            # verification scan.

            baseline = {
                "scan_id": scan_id,
                "project_name": project_name,
                "scanned_at": scanned_at,
                "files_scanned": files_scanned,
                "findings": copy.deepcopy(findings),
                "summary": copy.deepcopy(summary),
                "errors": copy.deepcopy(errors),
                "status": "completed",
                "scanner_version": result.get(
                    "scanner_version",
                    "unknown",
                ),
            }

            st.session_state.verification_baseline = (
                copy.deepcopy(baseline)
            )

            # Preserve compatibility with other
            # existing VulFin pages.

            st.session_state.last_scan_snapshot = (
                copy.deepcopy(baseline)
            )

            # ==========================================
            # 8. CLEAR OLD VERIFICATION RESULTS
            # ==========================================

            # A new initial scan starts a new
            # before-and-after comparison cycle.

            st.session_state.verification_results = None

            st.session_state.verification_after_scan = None

            st.session_state.previous_scan_snapshot = None

            # ==========================================
            # 9. UPDATE FRONTEND SESSION STATE
            # ==========================================

            st.session_state.findings = (
                copy.deepcopy(findings)
            )

            st.session_state.last_real_findings = (
                copy.deepcopy(findings)
            )

            st.session_state.demo_mode = False

            st.session_state.project_name = (
                project_name
            )

            st.session_state.scan_status = (
                "Scan completed"
            )

            st.session_state.scan_id = (
                scan_id
            )

            st.session_state.scan_timestamp = (
                scanned_at
            )

            st.session_state.files_scanned = (
                files_scanned
            )

            st.session_state.scan_files_scanned = (
                files_scanned
            )

            st.session_state.scan_summary = (
                copy.deepcopy(summary)
            )

            st.session_state.scan_errors = (
                copy.deepcopy(errors)
            )

            st.session_state.has_real_scan = True

            st.session_state.latest_scan_attempt_status = (
                "completed"
            )

            # ==========================================
            # 10. RESET PREVIOUS FINDING SELECTION
            # ==========================================

            if findings:

                st.session_state.selected_finding_id = (
                    findings[0].get("id")
                )

            else:

                st.session_state.selected_finding_id = None

            # Reset old AI remediation state.

            st.session_state.last_generated_prompt = None

            st.session_state.last_prompt_finding_id = None

            st.session_state.last_prompt_style = None

            st.session_state.review_status = {}

            # ==========================================
            # 11. NAVIGATE TO FINDINGS
            # ==========================================

            st.session_state.active_page = "Findings"

            st.rerun()

        # ==============================================
        # 12. HANDLE SCANNING ERRORS
        # ==============================================

        except ValueError as error:

            st.session_state.latest_scan_attempt_status = (
                "failed"
            )

            st.error(
                f"Invalid scan result: {error}"
            )

        except Exception as error:

            st.session_state.latest_scan_attempt_status = (
                "failed"
            )

            st.error(
                "Security scan failed: "
                f"{type(error).__name__}: {error}"
            )

    # ==================================================
    # 13. SCANNING WORKFLOW INFORMATION
    # ==================================================

    st.divider()

    with st.expander(
        "How VulFin Security Scanning Works"
    ):

        st.markdown(
            """
            **Step 1 — Upload Original Project**

            Upload the original website source code
            as a ZIP archive.

            **Step 2 — Security Analysis**

            VulFin scans supported source files
            and identifies potential vulnerabilities.

            **Step 3 — Review Findings**

            Open the Findings page to examine
            detected security issues.

            **Step 4 — Fix Vulnerabilities**

            Use Fix Assistant to obtain
            remediation suggestions.

            **Step 5 — Upload Corrected Project**

            Open the Verification page and upload
            a second ZIP containing the updated code.

            **Step 6 — Compare Results**

            VulFin compares the original and corrected
            scans to identify vulnerabilities that are
            no longer detected, still detected,
            or newly detected.
            """
        )
