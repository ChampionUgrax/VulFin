
EXPLANATIONS = {
    "SECRET-001": (
        "A credential may be stored directly in source code. "
        "If genuine and exposed, it could allow unauthorized use "
        "of the associated service."
    ),
    "CONFIG-001": (
        "A security-related configuration may be disabled. "
        "Review the setting and confirm whether it weakens "
        "protection in the application's actual environment."
    ),
    "INPUT-001": (
        "This code pattern may handle user-controlled input "
        "unsafely. Review how the input is validated, escaped, "
        "or passed to the relevant API."
    ),
    "AUTH-001": (
        "The scanner suspects a possible access-control weakness. "
        "Confirm that the server checks the user's identity "
        "and permissions before returning protected data."
    ),
}


def explain_finding(finding: dict) -> dict:
    """Add a human-readable explanation without inventing findings."""

    result = finding.copy()
    rule_id = finding.get("rule_id", "")

    result["explanation"] = EXPLANATIONS.get(
        rule_id,
        "Review the cited code and confirm the security impact "
        "before making changes.",
    )

    return result
