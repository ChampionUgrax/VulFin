
from intelligence.comparison import compare_findings


def test_compare_findings():
    before = [
        {"id": "A", "title": "Hardcoded credential"},
        {"id": "B", "title": "Unsafe HTML rendering"},
    ]

    after = [
        {"id": "B", "title": "Unsafe HTML rendering"},
        {"id": "C", "title": "New injection risk"},
    ]

    result = compare_findings(before, after)

    assert result["summary"] == {
        "resolved": 1,
        "still_present": 1,
        "new": 1,
    }

    assert result["resolved"][0]["id"] == "A"
    assert result["still_present"][0]["id"] == "B"
    assert result["new"][0]["id"] == "C"


def test_empty_scans():
    result = compare_findings([], [])

    assert result["summary"] == {
        "resolved": 0,
        "still_present": 0,
        "new": 0,
    }


def test_every_issue_resolved():
    before = [{"id": "A", "title": "Example issue"}]

    result = compare_findings(before, [])

    assert result["summary"]["resolved"] == 1
    assert result["summary"]["still_present"] == 0
    assert result["summary"]["new"] == 0


from intelligence.explanations import explain_finding
from intelligence.remediation import generate_repair_prompt


def test_explanation_and_repair_prompt():
    finding = {
        "id": "SL-SECRET-001-a1b2c3d4",
        "rule_id": "SECRET-001",
        "title": "Possible hardcoded credential",
        "severity": "high",
        "file": "src/config.js",
        "line": 12,
        "evidence": 'API_KEY = "sk-****"',
        "remediation": "Move the credential to secure configuration.",
    }

    explained = explain_finding(finding)

    assert explained["id"] == finding["id"]
    assert "credential" in explained["explanation"].lower()

    prompt = generate_repair_prompt(explained)

    assert "src/config.js" in prompt
    assert "SECRET-001" in prompt
    assert "secure configuration" in prompt
    assert "unrelated" in prompt.lower()
