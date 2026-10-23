
import csv
import io
import json
import re
from datetime import datetime

import streamlit as st


CSV_FIELDS = [
    "id",
    "title",
    "severity",
    "category",
    "file",
    "line",
    "status",
    "confidence",
    "evidence",
    "explanation",
    "recommendation",
]


# =====================================================
# 1. REPORT HELPERS
# =====================================================

def _safe_filename(name):
    """Create a filesystem-safe filename from the project name."""
    base = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        str(name or "vulfin-report"),
    ).strip(".-_")

    return base[:70] or "vulfin-report"


def _clean_value(value):
    """Convert values into text suitable for export."""
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def _redact_text(value):
    """Best-effort redaction of common credential formats."""
    text = _clean_value(value)

    credential_patterns = [
        r"\bsk_live_[0-9A-Za-z]{12,}\b",
        r"\brzp_(?:live|test)_[0-9A-Za-z]{10,}\b",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        r"\bAIza[0-9A-Za-z_-]{30,}\b",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b",
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^:\s]+:[^@\s]+@[^\s]+",
    ]

    for pattern in credential_patterns:
        text = re.sub(pattern, "[REDACTED]", text)

    text = re.sub(
        r"(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*)([^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )

    return text


def _safe_finding(finding):
    """Copy a finding and redact textual values before exporting."""
    safe = dict(finding)

    for field, value in list(safe.items()):
        if isinstance(value, str):
            safe[field] = _redact_text(value)

    return safe


# =====================================================
# 2. CSV REPORT GENERATION
# =====================================================

def _build_csv(findings):
    """Generate a CSV that can be opened in spreadsheet software."""
    buffer = io.StringIO(newline="")

    writer = csv.DictWriter(
        buffer,
        fieldnames=CSV_FIELDS,
        extrasaction="ignore",
    )

    writer.writeheader()

    for finding in findings:
        row = {
            field: _clean_value(finding.get(field))
            for field in CSV_FIELDS
        }

        # Reduce spreadsheet formula-injection risk when
        # untrusted values are opened in Excel or similar tools.
        for field, value in row.items():
            if value.lstrip().startswith(("=", "+", "-", "@")):
                row[field] = "'" + value

        writer.writerow(row)

    return buffer.getvalue()


# =====================================================
# 3. MARKDOWN REPORT GENERATION
# =====================================================

def _build_markdown(report):
    findings = report["findings"]
    counts = report["severity_summary"]

    lines = [
        "# VulFin Security Report",
        "",
        f"- **Project:** {report['project']}",
        f"- **Scan mode:** {report['mode']}",
        f"- **Scan status:** {report['scan_status']}",
        f"- **Scan ID:** {report['scan_id']}",
        f"- **Files scanned:** {report['files_scanned']}",
        f"- **Generated:** {report['generated_at']}",
        f"- **Total findings:** {len(findings)}",
        "",
        "> Automated findings are candidates for review. "
        "They do not guarantee exploitability or prove that "
        "a project is secure.",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity in ["critical", "high", "medium", "low", "info"]:
        lines.append(
            f"| {severity.title()} | {counts.get(severity, 0)} |"
        )

    lines.extend(["", "## Findings", ""])

    if not findings:
        lines.append("No findings were returned by the configured checks.")

    for index, finding in enumerate(findings, start=1):
        title = _clean_value(
            finding.get("title")
            or finding.get("id")
            or f"Finding {index}"
        )

        location = (
            f"{_clean_value(finding.get('file') or 'Unknown file')}:"
            f"{_clean_value(finding.get('line') or 'N/A')}"
        )

        lines.extend([
            f"### {index}. {title}",
            "",
            f"- **ID:** {_clean_value(finding.get('id') or 'N/A')}",
            f"- **Severity:** {_clean_value(finding.get('severity') or 'Unknown').upper()}",
            f"- **Category:** {_clean_value(finding.get('category') or 'Unknown')}",
            f"- **Location:** {location}",
            f"- **Status:** {_clean_value(finding.get('status') or 'open')}",
        ])

        confidence = finding.get("confidence")

        if confidence:
            lines.append(
                f"- **Confidence:** {_clean_value(confidence)}"
            )

        lines.extend([
            "",
            "**Evidence**",
            "",
            "```text",
            _clean_value(
                finding.get("evidence") or "No evidence provided"
            ).replace("```", "` ` `"),
            "```",
            "",
            "**Explanation**",
            "",
            _clean_value(
                finding.get("explanation")
                or "No explanation provided."
            ),
            "",
            "**Recommended remediation**",
            "",
            _clean_value(
                finding.get("recommendation")
                or "Review and validate this issue manually."
            ),
            "",
            "---",
            "",
        ])

    return "\n".join(lines).rstrip() + "\n"


# =====================================================
# 4. EXPORT REPORT PAGE
# =====================================================

def render_export_report():
    findings = st.session_state.get("findings", [])

    st.title("Export Report")
    st.caption(
        "Choose an export format and download the findings "
        "currently loaded in VulFin."
    )

    # Do not create an export before a scan or demo is loaded.
    has_real_scan = st.session_state.get("has_real_scan", False)
    demo_mode = st.session_state.get("demo_mode", False)

    if not findings and not has_real_scan and not demo_mode:
        st.info(
            "Complete a real scan before "
            "exporting a report."
        )
        return

    # -------------------------------------------------
    # REPORT METADATA
    # -------------------------------------------------

    project = (
        st.session_state.get("project_name")
        or "Unspecified project"
    )

    if demo_mode:
        mode = "DEMO"
    elif has_real_scan:
        mode = "REAL SCAN"
    else:
        mode = "NOT STARTED"

    files_scanned = st.session_state.get("scan_files_scanned")

    safe_findings = [
        _safe_finding(item)
        for item in findings
    ]

    report = {
        "product": "VulFin",
        "project": project,
        "mode": mode,
        "scan_status": st.session_state.get(
            "scan_status",
            "Not scanned",
        ),
        "scan_id": st.session_state.get("scan_id") or "Not provided",
        "files_scanned": (
            files_scanned
            if files_scanned is not None
            else "Not reported"
        ),
        "generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "severity_summary": {
            severity: sum(
                1
                for item in safe_findings
                if str(item.get("severity", "")).lower() == severity
            )
            for severity in [
                "critical",
                "high",
                "medium",
                "low",
                "info",
            ]
        },
        "findings": safe_findings,
    }

    # -------------------------------------------------
    # REPORT SUMMARY
    # -------------------------------------------------

    with st.container(border=True):
        st.subheader("Report summary")

        summary_cols = st.columns(4)

        summary_cols[0].markdown("**PROJECT**")
        summary_cols[0].write(project)

        summary_cols[1].markdown("**MODE**")
        summary_cols[1].write(mode)

        summary_cols[2].markdown("**STATUS**")
        summary_cols[2].write(report["scan_status"])

        summary_cols[3].markdown("**FINDINGS**")
        summary_cols[3].write(len(safe_findings))

    if mode == "DEMO":
        st.warning(
            "DEMO EXPORT — this report contains illustrative findings, "
            "not results from a real scan."
        )

    # -------------------------------------------------
    # FORMAT SELECTION DROPDOWN
    # -------------------------------------------------

    st.markdown("### Download report")

    export_format = st.selectbox(
        "Select export format",
        options=[
            "CSV (.csv)",
            "Markdown report (.md)",
            "JSON (.json)",
        ],
        index=0,
        key="export_report_format",
        help=(
            "CSV is suitable for Excel and Google Sheets. "
            "Markdown is a readable report. JSON preserves structured data."
        ),
    )

    # Prepare the selected format's data, filename and MIME type.
    filename_base = _safe_filename(project)

    if export_format == "CSV (.csv)":
        export_data = _build_csv(safe_findings)
        export_filename = f"{filename_base}-vulfin-findings.csv"
        export_mime = "text/csv"
        button_label = "Download CSV"

        st.caption(
            "Exports the current findings as rows and columns "
            "for Excel, Google Sheets or other spreadsheet software."
        )

    elif export_format == "Markdown report (.md)":
        export_data = _build_markdown(report)
        export_filename = f"{filename_base}-vulfin-report.md"
        export_mime = "text/markdown"
        button_label = "Download Markdown report"

        st.caption(
            "Exports a readable report containing scan metadata, "
            "severity counts, evidence and remediation recommendations."
        )

    else:
        export_data = json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
        export_filename = f"{filename_base}-vulfin-report.json"
        export_mime = "application/json"
        button_label = "Download JSON"

        st.caption(
            "Exports structured report metadata and findings as JSON."
        )

    # -------------------------------------------------
    # ONE DOWNLOAD BUTTON FOR THE SELECTED FORMAT
    # -------------------------------------------------

    st.download_button(
        label=button_label,
        data=export_data,
        file_name=export_filename,
        mime=export_mime,
        type="primary",
        use_container_width=True,
        help=f"Download the report in {export_format} format.",
    )

    st.caption(
        "Only findings currently loaded in VulFin are exported. "
        "Secret redaction uses best-effort pattern matching; review "
        "sensitive output before sharing reports."
    )
