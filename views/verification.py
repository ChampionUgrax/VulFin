
import copy

import pandas as pd
import streamlit as st

from services import vulfin_service


def display_findings(items):
    if not items:
        st.info("No findings in this category.")
        return

    rows = []

    for item in items:
        rows.append({
            "Issue": item.get(
                "title",
                item.get("issue", "Unknown issue")
            ),
            "Severity": str(
                item.get("severity", "Unknown")
            ).upper(),
            "File": item.get("file", "Unknown"),
            "Line": item.get("line", "-"),
        })

    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )


def render_verification():

    st.title("Fix Verification")

    st.caption(
        "Upload the corrected project and compare it "
        "against the original security scan."
    )

    # ==========================================
    # 1. CHECK INITIAL SCAN
    # ==========================================

    baseline = st.session_state.get(
        "verification_baseline"
    )

    if baseline is None:

        baseline = st.session_state.get(
            "last_scan_snapshot"
        )

    if baseline is None:

        st.warning(
            "No initial security scan found. "
            "Please scan the original project first."
        )

        if st.button(
            "Go to New Scan",
            use_container_width=True,
        ):
            st.session_state.active_page = "New Scan"
            st.rerun()

        return

    original_findings = baseline.get("findings", [])

    # ==========================================
    # 2. DISPLAY ORIGINAL SCAN
    # ==========================================

    st.subheader("1. Original Project")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Original Findings",
        len(original_findings)
    )

    col2.metric(
        "Files Scanned",
        baseline.get("files_scanned", 0)
    )

    col3.metric(
        "Scan Status",
        baseline.get("status", "Completed")
    )

    st.caption(
        f"Original project: "
        f"{baseline.get('project_name', 'Unknown')}"
    )

    # ==========================================
    # 3. UPLOAD CORRECTED PROJECT
    # ==========================================

    st.divider()

    st.subheader("2. Upload Fixed Project")

    st.write(
        "After fixing the vulnerabilities, create "
        "a new ZIP containing the updated source code."
    )

    fixed_zip = st.file_uploader(
        "Upload Fixed Project ZIP",
        type=["zip"],
        key="verification_fixed_zip",
        help=(
            "Upload the corrected version of "
            "the same project."
        ),
    )

    if fixed_zip is not None:

        st.success(
            f"Selected: {fixed_zip.name}"
        )

        st.caption(
            f"File size: "
            f"{fixed_zip.size / (1024 * 1024):.2f} MB"
        )

    # ==========================================
    # 4. RUN SECOND SECURITY SCAN
    # ==========================================

    if st.button(
        "Run Verification Scan",
        type="primary",
        use_container_width=True,
        disabled=fixed_zip is None,
        key="run_verification_scan",
    ):

        try:

            with st.spinner(
                "Scanning corrected project..."
            ):

                result = (
                    vulfin_service.run_security_scan(
                        fixed_zip.getvalue(),
                        fixed_zip.name,
                    )
                )

            if not isinstance(result, dict):
                raise ValueError(
                    "Scanner returned an invalid result."
                )

            status = str(
                result.get("status", "completed")
            ).lower()

            if status not in {
                "completed",
                "complete",
                "success",
                "succeeded",
            }:
                raise ValueError(
                    "The verification scan did not complete."
                )

            updated_findings = result.get(
                "findings", []
            )

            if not isinstance(updated_findings, list):
                raise ValueError(
                    "Scanner findings must be a list."
                )

            # ==================================
            # 5. COMPARE BOTH SCANS
            # ==================================

            comparison = (
                vulfin_service.compare_scan_results(
                    original_findings,
                    updated_findings,
                )
            )

            if not isinstance(comparison, dict):
                raise ValueError(
                    "Verification returned invalid results."
                )

            for category in (
                "fixed",
                "remaining",
                "new",
            ):
                if not isinstance(
                    comparison.get(category), list
                ):
                    raise ValueError(
                        f"Invalid comparison category: "
                        f"{category}"
                    )

            comparison.update({
                "previous_scan_id":
                    baseline.get("scan_id"),

                "current_scan_id":
                    result.get("scan_id"),

                "previous_project_name":
                    baseline.get("project_name"),

                "current_project_name":
                    result.get(
                        "project_name",
                        fixed_zip.name
                    ),

                "previous_scanned_at":
                    baseline.get("scanned_at"),

                "current_scanned_at":
                    result.get("scanned_at"),
            })

            # ==================================
            # 6. SAVE VERIFICATION RESULTS
            # ==================================

            st.session_state.verification_results = (
                comparison
            )

            st.session_state.verification_after_scan = (
                copy.deepcopy(result)
            )

            st.session_state.demo_mode = False

            st.success(
                "Verification scan completed successfully!"
            )

            st.rerun()

        except Exception as error:

            st.error(
                f"Verification failed: "
                f"{type(error).__name__}: {error}"
            )

    # ==========================================
    # 7. DISPLAY COMPARISON RESULTS
    # ==========================================

    results = st.session_state.get(
        "verification_results"
    )

    if results is None:
        st.info(
            "Upload the corrected ZIP and run "
            "verification to see the comparison."
        )
        return

    st.divider()

    st.subheader("3. Before vs After Comparison")

    fixed = results.get("fixed", [])
    remaining = results.get("remaining", [])
    new = results.get("new", [])

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "No Longer Detected",
        len(fixed)
    )

    c2.metric(
        "Still Detected",
        len(remaining)
    )

    c3.metric(
        "New Vulnerabilities",
        len(new)
    )

    st.divider()

    tabs = st.tabs([
        f"No Longer Detected ({len(fixed)})",
        f"Still Detected ({len(remaining)})",
        f"New Findings ({len(new)})",
    ])

    with tabs[0]:
        display_findings(fixed)

    with tabs[1]:
        display_findings(remaining)

    with tabs[2]:
        display_findings(new)

    st.warning(
        "A vulnerability disappearing from scan "
        "results does not guarantee that the issue "
        "is fully resolved. Review the actual code "
        "changes and scanner coverage."
    )
