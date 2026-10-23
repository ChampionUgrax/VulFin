import pandas as pd
import streamlit as st

from data import MOCK_VERIFICATION


def render_verification():
    st.title("Fix verification")
    st.caption(
        "Compare previous and current scans to track security findings."
    )

    results = st.session_state.get("verification_results")

    if results is None:
        if st.session_state.demo_mode:
            st.warning(
                "DEMO MODE: This comparison is sample data, "
                "not a real scan comparison."
            )
            st.dataframe(
                pd.DataFrame(MOCK_VERIFICATION),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info(
                "Run two real scans of the project to see a comparison here."
            )
        return

    st.markdown("### Comparison results")

    fixed = results.get("fixed", [])
    remaining = results.get("remaining", [])
    new = results.get("new", [])

    c1, c2, c3 = st.columns(3)
    c1.metric("No longer detected", len(fixed))
    c2.metric("Still detected", len(remaining))
    c3.metric("New findings", len(new))

    for heading, key in [
        ("No longer detected", "fixed"),
        ("Still detected", "remaining"),
        ("New findings", "new"),
    ]:
        st.markdown(f"### {heading}")
        items = results.get(key, [])

        if items:
            st.dataframe(
                pd.DataFrame([
                    {
                        "Issue": item.get("title", "Unknown issue"),
                        "Severity": item.get("severity", "unknown").upper(),
                        "File": item.get("file", "Unknown"),
                        "Line": item.get("line"),
                    }
                    for item in items
                ]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.success("No findings in this category.")

    st.caption(
        "A finding disappearing from a rescan is not proof that "
        "the entire website is secure."
    )