EXPLANATIONS = {
    "SECRET-001": (
        "A credential may be stored directly in source code. "
        "If genuine and exposed, it could allow unauthorized use "
        "of the associated service."
    ),
    "CONFIG-001": (
        "A security-related configuration may be disabled or too permissive. "
        "Review the setting in the application's actual environment."
    ),
    "INPUT-001": (
        "This code pattern may handle user-controlled input unsafely. "
        "Review how input is validated, escaped, or passed to the relevant API."
    ),
    "AUTH-001": (
        "The scanner suspects a possible access-control weakness. "
        "Confirm that the server checks identity and permissions before "
        "returning protected data."
    ),
}

# Map the rule IDs used by VulFin's custom scanner to explanation categories.
RULE_ALIASES = {
    "SEC-STRIPE": "SECRET-001",
    "SEC-RAZORPAY": "SECRET-001",
    "SEC-OPENAI": "SECRET-001",
    "SEC-AWS": "SECRET-001",
    "SEC-GOOGLE": "SECRET-001",
    "SEC-GITHUB": "SECRET-001",
    "SEC-DB-URI": "SECRET-001",
    "SEC-JWT": "SECRET-001",
    "CFG-CORS": "CONFIG-001",
    "CFG-DEBUG": "CONFIG-001",
    "VULN-SQLI": "INPUT-001",
}


def explain_finding(finding: dict) -> dict:
    """Add an explanation based on a known rule or finding category."""

    result = finding.copy()
    rule_id = str(finding.get("rule_id") or finding.get("id") or "")
    category = str(finding.get("category") or "").upper()

    explanation_key = RULE_ALIASES.get(rule_id, rule_id)

    if explanation_key not in EXPLANATIONS:
        if "SECRET" in category or "CREDENTIAL" in category:
            explanation_key = "SECRET-001"
        elif "CONFIG" in category:
            explanation_key = "CONFIG-001"
        elif "INPUT" in category or "SQL" in category:
            explanation_key = "INPUT-001"
        elif "AUTH" in category:
            explanation_key = "AUTH-001"

    result["explanation"] = EXPLANATIONS.get(
        explanation_key,
        "Review the cited code and confirm the security impact before making changes.",
    )

    return result