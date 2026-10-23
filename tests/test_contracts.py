from contracts import Finding, ScanResult, VerificationResult


def test_sample_finding_has_required_fields():
    finding: Finding = {
        "id": "F-001",
        "fingerprint": "secret:src/config.js:api-key",
        "title": "Hardcoded API credential",
        "severity": "high",
        "category": "exposed_secret",
        "file": "src/config.js",
        "line": 18,
        "evidence": 'apiKey = "sk-••••"',
        "recommendation": "Remove the exposed credential.",
        "status": "open",
    }

    assert finding["severity"] in {
        "critical", "high", "medium", "low", "info"
    }


def test_scan_result_shape():
    result: ScanResult = {
        "scan_id": "sample-001",
        "findings": [],
    }

    assert isinstance(result["scan_id"], str)
    assert isinstance(result["findings"], list)


def test_verification_result_shape():
    result: VerificationResult = {
        "fixed": [],
        "remaining": [],
        "new": [],
    }

    assert set(result.keys()) == {"fixed", "remaining", "new"}