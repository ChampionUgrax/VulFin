import streamlit as st
import pandas as pd

from data import count_severity


def render_dashboard():
    findings = st.session_state.findings

    st.title("Security overview")
    st.caption(
        "Understand your findings and decide what to fix first."
    )

    if not findings:
        with st.container(border=True):
            st.subheader("Review your first project")
            st.write(
                "Upload website source code, review security findings, "
                "prepare a repair prompt, and verify your changes."
            )
            st.info(
                "The scanner is not connected yet. "
                "Use Load demo findings in the sidebar to preview the UI."
            )
        return

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total findings", len(findings))
    c2.metric("Critical", count_severity(findings, "critical"))
    c3.metric("High", count_severity(findings, "high"))
    c4.metric("Medium", count_severity(findings, "medium"))

    st.markdown("### Current project")
    st.write(
        f"**Project:** {st.session_state.project_name or 'Sample website'}"
    )
    st.write(f"**Status:** {st.session_state.scan_status}")

    left, right = st.columns([1.3, 1])

    with left:
        st.markdown("#### Priority findings")

        priority = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }

        ordered = sorted(
            findings,
            key=lambda item: priority.get(
                item.get("severity", "info").lower(), 5
            ),
        )

        for item in ordered[:3]:
            with st.container(border=True):
                st.markdown(f"**{item['title']}**")
                st.caption(
                    f"{item['file']} · Line {item.get('line') or 'N/A'}"
                )
                st.write(item["recommendation"])

    with right:
        st.markdown("#### Severity distribution")

        counts = {
            level.title(): count_severity(findings, level)
            for level in ["critical", "high", "medium", "low", "info"]
        }

        st.bar_chart(pd.Series(counts, name="Findings"))