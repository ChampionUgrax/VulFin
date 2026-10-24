
import importlib


class BackendNotReadyError(RuntimeError):
    """Raised when a required backend module is not ready."""


def _load_backend_function(module_name: str, function_name: str):
    """Load a backend function from the project root or Intelligence package."""

    package_names = ("", "intelligence", "Intelligence")

    for package_name in package_names:
        qualified_name = (
            f"{package_name}.{module_name}"
            if package_name
            else module_name
        )

        try:
            module = importlib.import_module(qualified_name)

        except ModuleNotFoundError as exc:
            possible_module_names = {
                qualified_name,
                qualified_name.split(".")[0],
            }

            if exc.name not in possible_module_names:
                raise

            continue

        function = getattr(module, function_name, None)

        if callable(function):
            return function

        raise BackendNotReadyError(
            f"{qualified_name} must define a callable "
            f"'{function_name}()' function."
        )

    return None


def run_security_scan(zip_bytes: bytes, filename: str) -> dict:
    """Run the scanner on an uploaded project."""

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
        raise ValueError("The scanner must return a dictionary.")

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
    Generate a custom repair prompt with Gemini.
    Do not fall back to a hardcoded repair prompt.
    """
    remediation_function = _load_backend_function(
    "Intelligence.remediation",
    "generate_repair_prompt",
)

    normalized_finding.setdefault(
        "explanation",
        "Review the finding and verify whether the security risk is real.",
    )

    # Try both supported package capitalizations.
    repair_function = _load_backend_function(
        "llm_reviewer",
        "generate_repair_prompt_with_gemini",
    )

    if repair_function is None:
        raise BackendNotReadyError(
            "Gemini repair-prompt generation is unavailable. "
            "Ensure intelligence/llm_reviewer.py defines "
            "generate_repair_prompt_with_gemini(finding)."
        )

    prompt = repair_function(normalized_finding)

    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError(
            "Gemini returned an empty or invalid repair prompt."
        )

    return prompt.strip()


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
    """Compare findings when verification.py is unavailable."""

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
    """Compare earlier and later scan results."""

    verification_function = _load_backend_function(
        "verification",
        "compare_scans",
    )

    if verification_function is None:
        return _compare_findings(old_findings, new_findings)

    result = verification_function(
        old_findings,
        new_findings,
    )

    if not isinstance(result, dict):
        raise ValueError(
            "The verification module must return a dictionary."
        )

    for key in ("fixed", "remaining", "new"):
        if not isinstance(result.get(key), list):
            raise ValueError(
                f"The verification result must contain a '{key}' list."
            )

    return result


def analyze_finding_with_gemini(finding: dict) -> str:
    """Generate an AI security review for one finding."""

    if not isinstance(finding, dict):
        raise ValueError(
            "The selected finding must be a dictionary."
        )

    reviewer = _load_backend_function(
        "llm_reviewer",
        "review_finding_with_gemini",
    )

    if reviewer is None:
        raise BackendNotReadyError(
            "Gemini security review is unavailable. "
            "Ensure intelligence/llm_reviewer.py defines "
            "review_finding_with_gemini(finding)."
        )

    return reviewer(finding)
