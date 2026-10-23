import pandas as pd
import streamlit as st


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

    st.dataframe(
        pd.DataFrame([
            {
                "ID": item["id"],
                "Severity": item["severity"].upper(),
                "Issue": item["title"],
                "Category": item["category"],
                "File": item["file"],
                "Line": item.get("line"),
                "Status": item.get("status", "open"),
            }
            for item in visible
        ]),
        hide_index=True,
        use_container_width=True,
    )

    if not visible:
        st.info("No findings match the current filters.")
        return

    selected_id = st.selectbox(
        "Select a finding",
        [item["id"] for item in visible],
        format_func=lambda finding_id: next(
            item["title"]
            for item in visible
            if item["id"] == finding_id
        ),
    )

    finding = next(
        item for item in visible
        if item["id"] == selected_id
    )

    with st.container(border=True):
        st.subheader(finding["title"])

        st.markdown(
            f"**Severity:** {finding['severity'].upper()} "
            f" · **Category:** `{finding['category']}`"
        )

        st.markdown("**Location**")
        st.code(
            f"{finding['file']}:{finding.get('line') or 'N/A'}",
            language="text",
        )

        st.markdown("**Evidence**")
        st.code(finding.get("evidence", "No evidence provided"))

        st.markdown("**Why this matters**")
        st.write(
            finding.get("explanation", "Manual review required.")
        )

        st.markdown("**Recommended fix**")
        st.write(
            finding.get("recommendation", "Manual review required.")
        )

        st.caption(
            "Validate the evidence before treating a potential issue "
            "as a confirmed vulnerability."
        )