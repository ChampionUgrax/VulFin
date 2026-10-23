
def generate_repair_prompt(finding: dict) -> str:
    """Generate a focused repair prompt without exposing secret values."""

    file_path = finding.get("file", "unknown file")
    line = finding.get("line", "unknown")
    title = finding.get("title", "Potential security issue")
    rule_id = finding.get("rule_id", "UNKNOWN")
    explanation = finding.get(
        "explanation",
        "Review the finding and confirm the security risk.",
    )
    remediation = finding.get(
        "remediation",
        "Apply the appropriate secure coding practice.",
    )

    return f"""
You are fixing a security finding in a website codebase.

Finding: {title}
Rule ID: {rule_id}
File: {file_path}
Approximate line: {line}

Why it matters:
{explanation}

Required action:
{remediation}

Instructions:
1. Inspect the relevant code and confirm the issue.
2. Fix this specific issue using a secure approach.
3. Preserve unrelated application behavior.
4. Avoid unrelated refactoring or file changes.
5. Never print, log, or reproduce actual secrets or credentials.
6. Add or update a suitable test for the fix.
7. Explain what you changed and how to validate it.

If the finding is a false positive, explain the evidence rather
than making an unnecessary code change.

Do not claim the issue is fixed until the corrected code has
been tested and rescanned.
""".strip()
