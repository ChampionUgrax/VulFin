
import pandas as pd
import streamlit as st


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def _text(value):
    """Convert missing or non-string values into searchable text."""
    return "" if value is None else str(value)


def _finding_label(finding):
    """Return a readable label for a finding."""
    return _text(
        finding.get("title")
        or finding.get("id")
        or "Unknown finding"
    )


def _sort_findings(findings, sort_by, direction):
    """Sort findings without modifying the original list."""
    reverse = direction == "Descending"

    if sort_by == "Severity":
        return sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER.get(
                    _text(item.get("severity", "info")).lower(),
                    99,
                ),
                _finding_label(item).casefold(),
            ),
            reverse=reverse,
        )

    if sort_by == "Issue name":
        return sorted(
            findings,
            key=lambda item: _finding_label(item).casefold(),
            reverse=reverse,
        )

    if sort_by == "File path":
        return sorted(
            findings,
            key=lambda item: _text(item.get("file")).casefold(),
            reverse=reverse,
        )

    return sorted(
        findings,
        key=lambda item: _text(item.get("category")).casefold(),
        reverse=reverse,
    )


def render_findings():
    # Read findings safely from the existing Streamlit session.
    findings = st.session_state.get("findings", [])

    st.title("Security Findings")
    st.caption(
        "Search, sort, filter and inspect security findings, "
        "evidence, locations and recommended fixes."
    )

    # -------------------------------------------------
    # 1. SEARCH BAR
    # Render BEFORE checking whether findings exist,
    # so it remains visible when the list is empty.
    # -------------------------------------------------
    search_query = st.text_input(
        "🔎 Search across findings",
        placeholder=(
            "Search by issue title, file path, category or evidence..."
        ),
        help=(
            "Search is case-insensitive. For example, try "
            "'SQL injection', 'app.py' or 'HARDCODED_SECRET'."
        ),
        key="findings_search_v2",
    ).strip().casefold()

    # Keep the search bar visible even before the first scan.
    if not findings:
        st.info(
            "No findings are loaded yet"
            "complete a scan to search actual results."
        )
        return

    # -------------------------------------------------
    # 2. SORTING CONTROLS
    # -------------------------------------------------
    search_results_col, sort_col, order_col = st.columns(
        [2.5, 1.2, 1.1]
    )

    # Search results are filtered below; this column gives
    # the search field extra width in the layout.
    with search_results_col:
        st.caption("Search matches across the selected finding fields.")

    with sort_col:
        sort_by = st.selectbox(
            "Sort by",
            [
                "Severity",
                "Issue name",
                "File path",
                "Category",
            ],
            key="findings_sort_by_v2",
        )

    with order_col:
        direction = st.selectbox(
            "Order",
            ["Ascending", "Descending"],
            index=0,
            key="findings_sort_direction_v2",
            help=(
                "For severity, ascending places Critical first "
                "and descending places lower severities first."
            ),
        )

    # -------------------------------------------------
    # 3. SEVERITY AND CATEGORY FILTERS
    # -------------------------------------------------
    severities = sorted(
        {
            _text(item.get("severity", "info")).lower()
            for item in findings
        }
    )

    categories = sorted(
        {
            _text(item.get("category", "other"))
            for item in findings
        }
    )

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        selected_severities = st.multiselect(
            "Filter by severity",
            options=severities,
            default=severities,
            key="findings_severity_filter_v2",
        )

    with filter_col2:
        selected_categories = st.multiselect(
            "Filter by category",
            options=categories,
            default=categories,
            key="findings_category_filter_v2",
        )

    # -------------------------------------------------
    # 4. APPLY SEARCH AND FILTERS TOGETHER
    # Search only the four fields requested for this feature.
    # -------------------------------------------------
    visible = []

    for item in findings:
        severity = _text(item.get("severity", "info")).lower()
        category = _text(item.get("category", "other"))

        if severity not in selected_severities:
            continue

        if category not in selected_categories:
            continue

        searchable_text = " ".join(
            _text(item.get(field))
            for field in (
                "title",
                "file",
                "category",
                "evidence",
            )
        ).casefold()

        if search_query and search_query not in searchable_text:
            continue

        visible.append(item)

    # Sort only the filtered results.
    visible = _sort_findings(
        visible,
        sort_by,
        direction,
    )

    st.caption(
        f"Showing {len(visible)} of {len(findings)} finding(s)."
    )

    # -------------------------------------------------
    # 5. EMPTY SEARCH RESULTS
    # -------------------------------------------------
    if not visible:
        st.info(
            "No findings match your search and filters. "
            "Try a different keyword or change the selected filters."
        )
        return

    # -------------------------------------------------
    # 6. FINDINGS TABLE
    # -------------------------------------------------
    table_rows = [
        {
            "ID": item.get("id", "N/A"),
            "Severity": _text(
                item.get("severity", "unknown")
            ).upper(),
            "Issue": _finding_label(item),
            "Category": item.get("category", "other"),
            "File": item.get("file", "Unknown file"),
            "Line": item.get("line"),
            "Status": item.get("status", "open"),
        }
        for item in visible
    ]

    st.dataframe(
        pd.DataFrame(table_rows),
        hide_index=True,
        use_container_width=True,
    )

    # -------------------------------------------------
    # 7. FINDING DETAIL SELECTION
    # Handle missing or duplicate IDs safely.
    # -------------------------------------------------
    id_to_finding = {}
    options = []

    for index, item in enumerate(visible):
        option_id = _text(
            item.get("id")
            or item.get("fingerprint")
            or f"finding-{index}"
        )

        unique_id = option_id

        if unique_id in id_to_finding:
            unique_id = f"{option_id}#{index + 1}"

        id_to_finding[unique_id] = item
        options.append(unique_id)

    # If the previously selected finding is no longer visible,
    # remove the stale widget state before rendering the selector.
    current_selection = st.session_state.get("findings_selected_v2")

    if current_selection not in options:
        st.session_state.pop("findings_selected_v2", None)

    selected_id = st.selectbox(
        "Inspect a finding",
        options=options,
        format_func=lambda key: _finding_label(
            id_to_finding[key]
        ),
        key="findings_selected_v2",
    )

    finding = id_to_finding[selected_id]

    # Remember the selected finding for the other workflow pages.
    st.session_state.selected_finding_id = finding.get("id")

    # -------------------------------------------------
    # 8. FINDING DETAILS
    # -------------------------------------------------
    with st.container(border=True):
        st.subheader(_finding_label(finding))

        severity = _text(
            finding.get("severity", "unknown")
        ).upper()

        category = _text(
            finding.get("category", "other")
        )

        st.markdown(
            f"**Severity:** `{severity}`  ·  "
            f"**Category:** `{category}`"
        )

        st.markdown("**Location**")

        st.code(
            f"{finding.get('file', 'Unknown file')}:"
            f"{finding.get('line') or 'N/A'}",
            language="text",
        )

        st.markdown("**Evidence**")

        st.code(
            _text(
                finding.get("evidence")
                or "No evidence provided"
            ),
            language="text",
        )

        st.markdown("**Why this matters**")

        st.write(
            finding.get("explanation")
            or "Manual review required."
        )

        st.markdown("**Recommended fix**")

        st.write(
            finding.get("recommendation")
            or "Manual review required."
        )

        st.caption(
            "Validate the evidence before treating a potential "
            "issue as a confirmed vulnerability."
        )

        if st.button(
            "Generate repair prompt for this finding",
            type="primary",
            key="findings_open_fix_assistant",
        ):
            st.session_state.selected_finding_id = finding.get("id")
            st.session_state.active_page = "Fix Assistant"
            st.rerun()
