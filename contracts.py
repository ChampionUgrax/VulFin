from typing import TypedDict


Severity = str


class Finding(TypedDict):
    id: str
    fingerprint: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int | None
    evidence: str
    recommendation: str
    status: str


class ScanResult(TypedDict):
    scan_id: str
    findings: list[Finding]


class VerificationResult(TypedDict):
    fixed: list[Finding]
    remaining: list[Finding]
    new: list[Finding]