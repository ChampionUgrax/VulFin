import streamlit as st

from services.vulfin_service import generate_repair_prompt


def render_fix_assistant():

    findings = st.session_state.findings

    st.title("Fix Assistant")

    st.caption(
        "Generate a focused repair prompt for your AI coding assistant."
    )

    if not findings:
        st.info(
            "No findings are loaded."
        )
        return

    # Select an issue
    selected_id = st.selectbox(
        "Choose a finding",
        [item["id"] for item in findings],
        format_func=lambda finding_id: next(
            item["title"]
            for item in findings
            if item["id"] == finding_id
        ),
        key="fix_assistant_finding",
    )

    finding = next(
        item
        for item in findings
        if item["id"] == selected_id
    )

    # Display the selected issue
    st.markdown("### Finding context")

    with st.container(border=True):

        st.subheader(finding.get("title", "Unknown finding"))

        severity = finding.get("severity", "unknown").upper()

        st.markdown(f"**Severity:** {severity}")

        st.markdown(
            f"**Category:** `{finding.get('category', 'unknown')}`"
        )

        st.markdown("**Location**")

        st.code(
            f"{finding.get('file', 'Unknown file')}:"
            f"{finding.get('line') or 'N/A'}",
            language="text",
        )

        st.markdown("**Evidence**")

        st.code(
            finding.get("evidence", "No evidence provided"),
            language="text",
        )

        st.markdown("**Recommended direction**")

        st.write(
            finding.get(
                "recommendation",
                "Review and validate this issue manually.",
            )
        )

    st.markdown("### Generate repair prompt")

    st.write(
        "The prompt below gives a coding assistant context about the "
        "finding and asks it to propose a targeted fix."
    )

    try:
        with st.spinner("Preparing remediation prompt..."):
            prompt = generate_repair_prompt(finding)

        if not isinstance(prompt, str) or not prompt.strip():
            st.error("The remediation service returned an empty prompt.")
            return

        st.code(prompt, language="text")

        st.caption(
            "Use the copy control on the code block to copy this prompt."
        )

    except Exception as exc:
        st.error(f"Could not generate the repair prompt: {exc}")

    st.divider()

    st.markdown("### Important")

    st.info(
        "Review proposed changes before applying them. A generated repair "
        "prompt does not itself fix the issue; use the scanner to evaluate "
        "the updated code afterward."
    )

    if st.session_state.demo_mode:
        st.caption(
            "DEMO MODE: This prompt is based on an illustrative finding, "
            "not a real scanner result."
        )