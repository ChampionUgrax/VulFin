
import pandas as pd
import streamlit as st

from services.vulfin_service import analyze_finding_with_gemini


def render_findings():
    findings = st.session_state.findings

    st.title("Security findings")
    st.caption(
        "Filter findings and inspect evidence, locations and recommendations."
    )

    if not findings:
        st.info("Load demo findings or complete a real scan to view results.")
        return

    c1, c2 = st.columns(2)

    severities = sorted({
        item.get("severity", "info").lower()
        for item in findings
    })

    categories = sorted({
        item.get("category", "other")
        for item in findings
    })

    with c1:
        selected_severities = st.multiselect(
            "Filter by severity",
            severities,
            default=severities,
        )

    with c2:
        selected_categories = st.multiselect(
            "Filter by category",
            categories,
            default=categories,
        )

    visible = [
        item for item in findings
        if item.get("severity", "info").lower() in selected_severities
        and item.get("category", "other") in selected_categories
    ]

    st.caption(f"{len(visible)} finding(s) match your filters.")

    if visible:
        st.dataframe(
            pd.DataFrame([
                {
                    "ID": item.get("id", "N/A"),
                    "Severity": item.get("severity", "info").upper(),
                    "Issue": item.get("title", "Untitled finding"),
                    "Category": item.get("category", "other"),
                    "File": item.get("file", "unknown"),
                    "Line": item.get("line"),
                    "Status": item.get("status", "open"),
                }
                for item in visible
            ]),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No findings match the current filters.")
        return

    selected_id = st.selectbox(
        "Select a finding",
        [item.get("id") for item in visible],
        format_func=lambda finding_id: next(
            item.get("title", "Untitled finding")
            for item in visible
            if item.get("id") == finding_id
        ),
    )

    finding = next(
        item for item in visible
        if item.get("id") == selected_id
    )

    with st.container(border=True):
        st.subheader(finding.get("title", "Untitled finding"))

        st.markdown(
            f"**Severity:** {finding.get('severity', 'info').upper()} "
            f" · **Category:** `{finding.get('category', 'other')}`"
        )

        st.markdown("**Location**")
        st.code(
            f"{finding.get('file', 'unknown')}:{finding.get('line') or 'N/A'}",
            language="text",
        )

        st.markdown("**Evidence**")
        st.code(
            str(finding.get("evidence", "No evidence provided")),
            language="text",
        )

        st.markdown("**Why this matters**")
        st.write(
            finding.get("explanation", "Manual review required.")
        )

        st.markdown("**Recommended fix**")
        st.write(
            finding.get("recommendation", "Manual review required.")
        )

        st.divider()
        st.markdown("### AI security review")

        finding_key = str(finding.get("id", selected_id))

        if st.button(
            "Analyze with Gemini",
            key=f"gemini_review_{finding_key}",
            type="primary",
        ):
            try:
                with st.spinner("Gemini is reviewing the finding..."):
                    review = analyze_finding_with_gemini(finding)

                if not isinstance(review, str) or not review.strip():
                    raise ValueError(
                        "Gemini returned an empty response."
                    )

                st.session_state.setdefault("gemini_reviews", {})
                st.session_state["gemini_reviews"][finding_key] = review
                st.success("Gemini analysis completed.")

            except Exception as exc:
                # Show the actual exception to help diagnose the problem.
                st.error(
                    f"Gemini analysis failed: {type(exc).__name__}: {exc}"
                )

        saved_reviews = st.session_state.get("gemini_reviews", {})
        saved_review = saved_reviews.get(finding_key)

        if saved_review:
            st.markdown("#### Gemini's assessment")
            st.markdown(saved_review)
            st.caption(
                "AI-generated guidance is not proof of a vulnerability "
                "or a verified fix. Review and test suggestions manually."
            )

        st.caption(
            "Validate the evidence before treating a potential issue "
            "as a confirmed vulnerability."
        )
