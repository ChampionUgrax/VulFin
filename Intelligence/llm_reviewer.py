
import os
import json

import streamlit as st
from google import genai


def _get_setting(name: str, default: str = "") -> str:
    """Read settings from Streamlit secrets or environment variables."""
    try:
        value = st.secrets.get(name)
    except Exception:
        value = None

    if value:
        return str(value).strip()

    return os.getenv(name, default).strip()


def review_finding_with_gemini(finding: dict) -> str:
    """Review a VulFin security finding with Gemini Flash Lite."""

    if not isinstance(finding, dict):
        raise ValueError("The security finding must be a dictionary.")

    api_key = _get_setting("GEMINI_API_KEY")
    model = _get_setting(
        "GEMINI_MODEL",
        "gemini-flash-lite-latest",
    )
    model = model.removeprefix("models/").strip()

    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is missing from .streamlit/secrets.toml."
        )

    if not model:
        model = "gemini-flash-lite-latest"

    # Limit the request to relevant finding metadata.
    details = {
        "title": str(finding.get("title") or "Unknown issue")[:120],
        "severity": str(finding.get("severity") or "Unknown")[:30],
        "category": str(finding.get("category") or "Unknown")[:50],
        "file": str(finding.get("file") or "Unknown")[:120],
        "line": str(finding.get("line") or "Unknown")[:20],
        "explanation": str(
            finding.get("explanation") or "Not provided."
        )[:350],
        "recommendation": str(
            finding.get("recommendation")
            or finding.get("remediation")
            or "Manual review required."
        )[:350],
    }

    prompt = f"""
You are VulFin, an application security reviewer.

Assess this finding using only the provided metadata:
{json.dumps(details, ensure_ascii=False)}

Respond in concise Markdown with these five headings:
- Assessment: confirmed or suspected, and why.
- Impact: possible consequences.
- Validation: how to verify the issue safely.
- Remediation: the defensive fix to consider.
- Verification: how to test the fix.

Keep the response under 150 words.
Do not claim to have inspected source code.
State uncertainty clearly.
"""

    client = genai.Client(
        api_key=api_key,
        http_options={"timeout": 30000},
    )

    try:
        interaction = client.interactions.create(
            model=model,
            input=prompt,
        )

        review = getattr(interaction, "output_text", None)

        if not review or not review.strip():
            status = getattr(interaction, "status", "unknown")
            raise RuntimeError(
                f"Gemini returned no review text. Status: {status}. "
                "Please retry after checking the interaction status."
            )

        return review.strip()

    except Exception as exc:
        message = str(exc)
        lowered = message.lower()

        if "503" in message or "unavailable" in lowered:
            raise RuntimeError(
                "Gemini is temporarily unavailable. Please wait and retry."
            ) from exc

        if "504" in message or "deadline_exceeded" in lowered:
            raise RuntimeError(
                "Gemini's server deadline expired. Try again later."
            ) from exc

        if "timeout" in lowered or "timed out" in lowered:
            raise RuntimeError(
                "The Gemini request timed out. Please retry."
            ) from exc

        raise RuntimeError(
            f"Gemini API error ({type(exc).__name__}): {message}"
        ) from exc

    finally:
        client.close()

def generate_repair_prompt_with_gemini(finding: dict) -> str:
    """Generate a tailored code-repair prompt for a security finding."""

    import json

    if not isinstance(finding, dict):
        raise ValueError("The security finding must be a dictionary.")

    api_key = _get_setting("GEMINI_API_KEY")
    model = _get_setting(
        "GEMINI_MODEL",
        "gemini-flash-lite-latest",
    )
    model = model.removeprefix("models/").strip()

    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is missing from .streamlit/secrets.toml."
        )

    if not model:
        model = "gemini-flash-lite-latest"

    # Include relevant details, but never send raw secret values.
    details = {
        "title": str(finding.get("title") or "Security vulnerability")[:150],
        "severity": str(finding.get("severity") or "Unknown")[:30],
        "category": str(finding.get("category") or "Unknown")[:60],
        "file": str(finding.get("file") or "Unknown")[:200],
        "line": str(finding.get("line") or "Unknown")[:30],
        "explanation": str(
            finding.get("explanation") or "No explanation provided."
        )[:600],
        "recommendation": str(
            finding.get("recommendation")
            or finding.get("remediation")
            or "Determine the appropriate defensive fix."
        )[:600],
    }

    prompt = f"""
You are VulFin's senior application security engineer.

Generate a CUSTOM REPAIR PROMPT for another AI coding assistant
to fix the security finding described below.

FINDING:
{json.dumps(details, ensure_ascii=False)}

Write a ready-to-copy prompt that instructs the coding assistant to:

1. Inspect the relevant source file and surrounding code before editing.
2. Identify the root cause and confirm whether the vulnerability is real.
3. Make the smallest appropriate code change to fix the confirmed issue.
4. Preserve existing functionality, architecture, naming, and unrelated code.
5. Avoid hardcoding secrets, weakening security controls, or introducing
   new dependencies unless genuinely necessary.
6. Add or update appropriate tests for the fix.
7. Explain the files changed, the fix, and how to run the tests.
8. If the finding cannot be confirmed from the available information,
   inspect the code first and explain the uncertainty rather than inventing
   code changes.

Tailor the instructions specifically to this finding and its vulnerability
category. Do not merely repeat a generic security checklist.
Do not invent source code, file contents, or confirmed root causes.

Return ONLY the final repair prompt, ready to copy and paste.
Do not perform the repair yourself.
Keep the repair prompt concise but sufficiently detailed.
"""

    client = genai.Client(
        api_key=api_key,
        http_options={"timeout": 30000},
    )

    try:
        interaction = client.interactions.create(
            model=model,
            input=prompt,
        )

        result = getattr(interaction, "output_text", None)

        if not result or not result.strip():
            status = getattr(interaction, "status", "unknown")
            raise RuntimeError(
                f"Gemini generated no repair prompt. Status: {status}"
            )

        return result.strip()

    except Exception as exc:
        raise RuntimeError(
            f"Gemini repair-prompt generation failed "
            f"({type(exc).__name__}): {exc}"
        ) from exc

    finally:
        client.close()
