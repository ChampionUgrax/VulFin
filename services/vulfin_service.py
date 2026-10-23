import importlib

from data import make_repair_prompt


class BackendNotReadyError(RuntimeError):
    """Raised when a required backend module is not ready."""


def _load_backend_function(module_name: str, function_name: str):
    """
    Load a backend function dynamically.

    Returns None when the entire module is missing.
    Raises BackendNotReadyError when the module exists
    but does not expose the expected function.
    """
    try:
        module = importlib.import_module(module_name)

    except ModuleNotFoundError as exc:
        # Only handle the missing backend module itself.
        # Don't hide missing dependencies inside that module.
        if exc.name == module_name:
            return None
        raise

    function = getattr(module, function_name, None)

    if not callable(function):
        raise BackendNotReadyError(
            f"{module_name}.py must define a callable "
            f"'{function_name}()' function."
        )

    return function


def run_security_scan(zip_bytes: bytes, filename: str) -> dict:
    """
    Run the scanner.

    Expected function:
        scanner.scan_project(zip_bytes, filename)

    Expected result:
        {
            "scan_id": "...",
            "findings": [...]
        }
    """
    scan_function = _load_backend_function(
        "scanner",
        "scan_project",
    )

    if scan_function is None:
        raise BackendNotReadyError(
            "scanner.py has not been integrated yet. "
            "The uploaded file has not been scanned."
        )

    result = scan_function(zip_bytes, filename)

    if not isinstance(result, dict):
        raise ValueError(
            "The scanner must return a dictionary."
        )

    findings = result.get("findings")

    if not isinstance(findings, list):
        raise ValueError(
            "The scanner result must contain a 'findings' list."
        )

    if not all(isinstance(item, dict) for item in findings):
        raise ValueError(
            "Every finding must be a dictionary."
        )

    return result


def generate_repair_prompt(finding: dict) -> str:
    """
    Generate a repair prompt using remediation.py
    or use the local template if that module is absent.
    """
    remediation_function = _load_backend_function(
    "Intelligence.remediation",
    "generate_repair_prompt",
)

    if remediation_function is None:
        return make_repair_prompt(finding)

    prompt = remediation_function(finding)

    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError(
            "The remediation module returned an empty or invalid prompt."
        )

    return prompt


def _finding_key(finding: dict) -> str:
    """Create a key to match findings across scans."""
    fingerprint = finding.get("fingerprint")

    if fingerprint:
        return str(fingerprint)

    return "|".join(
        [
            str(finding.get("category", "unknown")),
            str(finding.get("file", "unknown")),
            str(finding.get("title", "unknown")),
        ]
    )


def _compare_findings(
    old_findings: list[dict],
    new_findings: list[dict],
) -> dict:
    """Fallback comparison when verification.py is absent."""
    old_map = {
        _finding_key(item): item
        for item in old_findings
    }

    new_map = {
        _finding_key(item): item
        for item in new_findings
    }

    fixed = [
        old_map[key]
        for key in old_map
        if key not in new_map
    ]

    remaining = [
        new_map[key]
        for key in new_map
        if key in old_map
    ]

    newly_detected = [
        new_map[key]
        for key in new_map
        if key not in old_map
    ]

    return {
        "fixed": fixed,
        "remaining": remaining,
        "new": newly_detected,
    }


def compare_scan_results(
    old_findings: list[dict],
    new_findings: list[dict],
) -> dict:
    """
    Compare earlier and later scan results.

    Expected function in verification.py:
        compare_scans(old_findings, new_findings)

    Expected result:
        {
            "fixed": [...],
            "remaining": [...],
            "new": [...]
        }
    """
    verification_function = _load_backend_function(
        "verification",
        "compare_scans",
    )

    if verification_function is None:
        return _compare_findings(
            old_findings,
            new_findings,
        )

    result = verification_function(
        old_findings,
        new_findings,
    )

    if not isinstance(result, dict):
        raise ValueError(
            "The verification module must return a dictionary."
        )

    required_keys = ("fixed", "remaining", "new")

    for key in required_keys:
        if not isinstance(result.get(key), list):
            raise ValueError(
                f"The verification result must contain a '{key}' list."
            )

    return result