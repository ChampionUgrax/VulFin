"""VibeShield - Universal Security Scanner Engine.

Supports local folders, ZIP archives, single source files, and authorized public URLs.
Uses Python's standard library only. Static checks are heuristic and do not prove exploitability.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

SCANNER_VERSION = "1.1.0"
SCANNABLE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".html", ".json", ".env",
    ".vue", ".php", ".yaml", ".yml", ".toml", ".xml", ".sh",
}
IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "__pycache__",
    ".venv", "venv", ".idea", ".vscode",
}

# Resource limits. Tune these for the environment where the scanner is deployed.
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_HTTP_BYTES = 2 * 1024 * 1024
MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_ZIP_UNPACKED_BYTES = 150 * 1024 * 1024
MAX_ZIP_FILES = 5000
HTTP_TIMEOUT_SECONDS = 8
MAX_JS_BUNDLES = 4

RULES: List[Dict[str, Any]] = [
    {"id": "SEC-STRIPE", "title": "Possible exposed Stripe live secret key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "Stripe Live Secret Key"},
    {"id": "SEC-RAZORPAY", "title": "Possible exposed Razorpay secret key", "pattern": r"rzp_(?:live|test)_[0-9a-zA-Z]{14,}", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "Razorpay API Key"},
    {"id": "SEC-OPENAI", "title": "Possible exposed OpenAI / LLM API key", "pattern": r"sk-(?:proj-)?[a-zA-Z0-9_-]{32,}", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "OpenAI API Key"},
    {"id": "SEC-AWS", "title": "Possible exposed AWS access key ID", "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "AWS Access Key"},
    {"id": "SEC-GOOGLE", "title": "Possible exposed Google API key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "HIGH", "category": "HARDCODED_SECRET", "secret_type": "Google API Key"},
    {"id": "SEC-GITHUB", "title": "Possible exposed GitHub token", "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "GitHub Token"},
    {"id": "SEC-DB-URI", "title": "Possible database connection string with credentials", "pattern": r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+", "severity": "CRITICAL", "category": "HARDCODED_SECRET", "secret_type": "Database Connection String"},
    # This detects JWT-shaped values only; it does NOT prove a Supabase service-role key.
    {"id": "SEC-JWT", "title": "JWT-shaped token found; verify whether it is sensitive", "pattern": r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}", "severity": "HIGH", "category": "POSSIBLE_SECRET", "secret_type": "JWT-shaped token"},
    {"id": "CFG-CORS", "title": "Potential wildcard CORS configuration", "pattern": r"(?:cors\s*\(\s*\{\s*origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*:\s*[\"']\*[\"'])", "severity": "HIGH", "category": "INSECURE_CONFIGURATION", "secret_type": None},
    {"id": "CFG-DEBUG", "title": "Potential debug mode enabled", "pattern": r"(?i)(?:debug\s*=\s*True|NODE_ENV\s*[:=]\s*[\"']development[\"'])", "severity": "MEDIUM", "category": "INSECURE_CONFIGURATION", "secret_type": None},
    {"id": "VULN-SQLI", "title": "Potential SQL injection via dynamic query construction", "pattern": r"(?i)(?:execute|query)\s*\(\s*(?:f[\"'].*?SELECT.*?\{.*?\}|[\"'].*?SELECT.*?[\"']\s*\+)", "severity": "HIGH", "category": "INSECURE_CODE", "secret_type": None},
]
ADMIN_ROUTE_PATTERN = re.compile(r"(?i)(?:app\.(?:get|post|put|delete|patch)|router\.(?:get|post|put|delete|patch)|@app\.route)\s*\(\s*[\"']/((?:api/)?)admin")
AUTH_KEYWORDS = {"auth", "protect", "jwt", "token", "verify", "session", "adminonly", "isauthenticated", "login_required"}
PLACEHOLDERS = ("your_key_here", "your-api-key", "xxxx", "dummy", "placeholder", "changeme", "example")


def _result(target: str, target_type: str, status: str, findings: Optional[List[Dict[str, Any]]] = None,
            files_scanned: int = 0, errors: Optional[List[str]] = None) -> Dict[str, Any]:
    findings = findings or []
    counts = {level.lower(): sum(1 for f in findings if f.get("severity") == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    report: Dict[str, Any] = {
        "scanner_version": SCANNER_VERSION,
        "status": status,
        "target": target,
        "target_type": target_type,
        "health_score": calculate_health_score(findings) if status == "completed" else None,
        "files_scanned": files_scanned,
        "findings": findings,
        "summary": {**counts, "total": len(findings)},
        "errors": errors or [],
    }
    return report


def mask_secret(secret: str) -> str:
    """Mask a matched secret before it is included in report evidence."""
    if len(secret) <= 8:
        return "[REDACTED]"
    return f"{secret[:3]}…[REDACTED]…{secret[-4:]}"


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("//", "#", "/*", "*", "<!--"))


def _is_placeholder_match(match_text: str) -> bool:
    lowered = match_text.lower()
    return any(token in lowered for token in PLACEHOLDERS)


def _safe_evidence(line: str, matches: List[Tuple[int, int, str]], limit: int = 160) -> str:
    """Redact every detected secret match and common credential assignments in evidence."""
    safe = line.rstrip("\r\n")
    for start, end, value in sorted(matches, reverse=True):
        safe = safe[:start] + mask_secret(value) + safe[end:]
    safe = re.sub(
        r"(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*)([\"'][^\"']*[\"']|[^,;\s]+)",
        r"\1[REDACTED]", safe,
    )
    return safe[:limit]


def scan_file(file_path: str, relative_path: str) -> List[Dict[str, Any]]:
    """Run heuristic source/config checks on a single file."""
    findings: List[Dict[str, Any]] = []
    try:
        if os.path.getsize(file_path) > MAX_FILE_BYTES:
            return [{"id": "SCAN-FILE-LIMIT", "title": "File skipped: size limit exceeded", "severity": "LOW",
                     "file": relative_path, "line": 1, "evidence": f"File exceeds {MAX_FILE_BYTES} bytes.",
                     "category": "SCAN_LIMIT", "secret_type": None, "confidence": "high"}]
        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except (OSError, UnicodeError) as exc:
        return [{"id": "SCAN-FILE-ERROR", "title": "Unable to read file", "severity": "LOW",
                 "file": relative_path, "line": 1, "evidence": type(exc).__name__,
                 "category": "SCAN_ERROR", "secret_type": None, "confidence": "high"}]

    if os.path.basename(file_path) == ".env":
        findings.append({"id": "CFG-ENV-FILE", "title": "Environment file included in scanned source",
                         "severity": "HIGH", "file": relative_path, "line": 1,
                         "evidence": "Found a .env file. Confirm it is not committed or publicly served.",
                         "category": "INSECURE_CONFIGURATION", "secret_type": "Environment Configuration",
                         "confidence": "medium"})

    for line_idx, line in enumerate(lines, start=1):
        # Do not discard an entire line merely because it also uses an environment lookup.
        if _is_comment_line(line):
            continue
        for rule in RULES:
            try:
                matches = list(re.finditer(rule["pattern"], line))
            except re.error:
                continue
            matches = [m for m in matches if not _is_placeholder_match(m.group(0))]
            for match in matches:
                # Redact every secret-like value on the line, not only the current match.
                all_secret_spans: List[Tuple[int, int, str]] = []
                for secret_rule in RULES:
                    if secret_rule["category"] not in {"HARDCODED_SECRET", "POSSIBLE_SECRET"}:
                        continue
                    try:
                        for secret_match in re.finditer(secret_rule["pattern"], line):
                            if not _is_placeholder_match(secret_match.group(0)):
                                all_secret_spans.append((secret_match.start(), secret_match.end(), secret_match.group(0)))
                    except re.error:
                        continue
                evidence = _safe_evidence(line, all_secret_spans)
                findings.append({"id": rule["id"], "title": rule["title"], "severity": rule["severity"],
                                 "file": relative_path, "line": line_idx, "evidence": evidence,
                                 "category": rule["category"], "secret_type": rule["secret_type"],
                                 "confidence": "medium" if rule["id"] in {"SEC-JWT", "VULN-SQLI", "CFG-CORS", "CFG-DEBUG"} else "high"})

        if ADMIN_ROUTE_PATTERN.search(line):
            context = "".join(lines[max(0, line_idx - 2):min(len(lines), line_idx + 3)]).lower()
            if not any(word in context for word in AUTH_KEYWORDS):
                findings.append({"id": "SEC-POSSIBLE-MISSING-AUTH", "title": "Admin route may lack nearby authentication checks",
                                 "severity": "HIGH", "file": relative_path, "line": line_idx,
                                 "evidence": line.strip()[:120], "category": "MISSING_ACCESS_CONTROL",
                                 "secret_type": None, "confidence": "low"})
    return findings


def calculate_health_score(findings: List[Dict[str, Any]]) -> int:
    """Simple heuristic score; not a formal security rating."""
    deductions = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = 100 - sum(deductions.get(f.get("severity", "LOW"), 5) for f in findings)
    return max(0, min(100, score))


def scan_project(directory_path: str) -> Dict[str, Any]:
    if not os.path.isdir(directory_path):
        return _result(directory_path, "directory", "failed", errors=[f"Directory not found: {directory_path}"])
    findings: List[Dict[str, Any]] = []
    scanned = 0
    try:
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SCANNABLE_EXTENSIONS and filename != ".env":
                    continue
                full_path = os.path.join(root, filename)
                relative = os.path.relpath(full_path, directory_path).replace("\\", "/")
                findings.extend(scan_file(full_path, relative))
                scanned += 1
    except OSError as exc:
        return _result(directory_path, "directory", "failed", findings, scanned, [f"Directory traversal failed: {type(exc).__name__}"])
    return _result(directory_path, "directory", "completed", findings, scanned)


def scan_single_file(file_path: str) -> Dict[str, Any]:
    if not os.path.isfile(file_path):
        return _result(file_path, "file", "failed", errors=[f"File not found: {file_path}"])
    findings = scan_file(file_path, os.path.basename(file_path))
    return _result(file_path, "file", "completed", findings, 1)


def _safe_zip_members(zip_ref: zipfile.ZipFile) -> Tuple[bool, str]:
    infos = zip_ref.infolist()
    if len(infos) > MAX_ZIP_FILES:
        return False, f"ZIP contains more than {MAX_ZIP_FILES} entries."
    total_uncompressed = 0
    for info in infos:
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part == ".." for part in path.parts) or (path.parts and ":" in path.parts[0]):
            return False, "ZIP contains an unsafe path."
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ZIP_UNPACKED_BYTES:
            return False, "ZIP exceeds the uncompressed size limit."
        if info.file_size > 0 and info.compress_size == 0:
            return False, "ZIP contains a suspicious compression entry."
        if info.compress_size > 0 and info.file_size / info.compress_size > 1000:
            return False, "ZIP contains an excessive compression ratio."
    return True, ""


def scan_zip(zip_path: str) -> Dict[str, Any]:
    if not os.path.isfile(zip_path):
        return _result(zip_path, "zip_archive", "failed", errors=[f"ZIP archive not found: {zip_path}"])
    try:
        if os.path.getsize(zip_path) > MAX_ZIP_BYTES:
            return _result(zip_path, "zip_archive", "failed", errors=[f"ZIP exceeds {MAX_ZIP_BYTES} bytes."])
        with zipfile.ZipFile(zip_path, "r") as archive:
            safe, reason = _safe_zip_members(archive)
            if not safe:
                return _result(zip_path, "zip_archive", "failed", errors=[reason])
            with tempfile.TemporaryDirectory(prefix="vibeshield_") as temp_dir:
                # Extract only after all member names and aggregate limits have been validated.
                archive.extractall(temp_dir)
                report = scan_project(temp_dir)
                report["target"] = zip_path
                report["target_type"] = "zip_archive"
                return report
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        return _result(zip_path, "zip_archive", "failed", errors=[f"Unable to process ZIP: {type(exc).__name__}"])


def _validate_public_http_url(url: str) -> Tuple[bool, str]:
    """Best-effort SSRF guard. Deployment-level outbound network restrictions are still required."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "Only HTTP and HTTPS URLs are allowed."
        if not parsed.hostname or parsed.username or parsed.password:
            return False, "URL must include a hostname and must not contain embedded credentials."
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
            return False, "Local hostnames are not allowed."
        try:
            literal_ip = ipaddress.ip_address(hostname)
            addresses = [literal_ip]
        except ValueError:
            try:
                infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            except OSError:
                return False, "Hostname could not be resolved."
            addresses = []
            for info in infos:
                try:
                    addresses.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        if not addresses:
            return False, "Hostname did not resolve to a valid IP address."
        if any(not addr.is_global for addr in addresses):
            return False, "Private, loopback, link-local, or otherwise non-public IP destinations are not allowed."
        return True, ""
    except (ValueError, UnicodeError):
        return False, "Invalid URL."


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        ok, reason = _validate_public_http_url(absolute)
        if not ok:
            raise urllib.error.URLError(f"Redirect blocked: {reason}")
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def _fetch_public_url(url: str, max_bytes: int, timeout: int = HTTP_TIMEOUT_SECONDS):
    ok, reason = _validate_public_http_url(url)
    if not ok:
        raise ValueError(reason)
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "VibeShield-Security-Auditor/1.1"})
    with opener.open(request, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Response exceeds {max_bytes} bytes.")
        return data, dict(response.headers.items()), response.geturl()


def scan_live_url(url: str) -> Dict[str, Any]:
    """Check selected response headers and scan the HTML plus a few public JS bundles.

    Only scan sites you own or have permission to assess. URL validation is defense in depth;
    run this behind a network egress policy that blocks private/internal ranges.
    """
    url = url.strip()
    if not url:
        return _result(url, "live_url", "failed", errors=["URL is empty."])
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    try:
        html_bytes, headers_dict, final_url = _fetch_public_url(url, MAX_HTTP_BYTES)
        html_content = html_bytes.decode("utf-8", errors="replace")
    except (ValueError, OSError, urllib.error.URLError, TimeoutError) as exc:
        return _result(url, "live_url", "failed", errors=[f"Failed to fetch target: {str(exc)[:200]}"])

    findings: List[Dict[str, Any]] = []
    scanned_count = 1
    normalized_headers = {key.lower(): value.strip() for key, value in headers_dict.items()}
    final_scheme = urllib.parse.urlsplit(final_url).scheme.lower()
    if final_scheme != "https":
        findings.append({"id": "SEC-NO-HTTPS", "title": "Website uses unencrypted HTTP", "severity": "CRITICAL",
                         "file": final_url, "line": 1, "evidence": "Final response URL uses HTTP.",
                         "category": "INSECURE_CONFIGURATION", "secret_type": None, "confidence": "high"})
    elif "strict-transport-security" not in normalized_headers:
        findings.append({"id": "SEC-MISSING-HSTS", "title": "Missing HSTS header", "severity": "MEDIUM",
                         "file": "HTTP Headers", "line": 1, "evidence": "Strict-Transport-Security header is absent.",
                         "category": "INSECURE_CONFIGURATION", "secret_type": None, "confidence": "high"})
    if "content-security-policy" not in normalized_headers:
        findings.append({"id": "SEC-MISSING-CSP", "title": "Missing Content Security Policy header", "severity": "MEDIUM",
                         "file": "HTTP Headers", "line": 1, "evidence": "Content-Security-Policy header is absent.",
                         "category": "INSECURE_CONFIGURATION", "secret_type": None, "confidence": "medium"})
    if normalized_headers.get("access-control-allow-origin", "") == "*":
        findings.append({"id": "CFG-CORS", "title": "Live server allows wildcard CORS origin", "severity": "HIGH",
                         "file": "HTTP Headers", "line": 1, "evidence": "Access-Control-Allow-Origin: *",
                         "category": "INSECURE_CONFIGURATION", "secret_type": None, "confidence": "medium"})

    with tempfile.TemporaryDirectory(prefix="vibeshield_http_") as temp_dir:
        html_path = os.path.join(temp_dir, "index.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html_content)
        findings.extend(scan_file(html_path, "index.html"))

        script_sources = re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", html_content, re.IGNORECASE)
        seen = set()
        for src in script_sources:
            if scanned_count >= 1 + MAX_JS_BUNDLES:
                break
            script_url = urllib.parse.urljoin(final_url, src)
            if script_url in seen:
                continue
            seen.add(script_url)
            try:
                js_bytes, _, _ = _fetch_public_url(script_url, MAX_HTTP_BYTES, timeout=5)
                js_content = js_bytes.decode("utf-8", errors="replace")
                js_path = os.path.join(temp_dir, f"bundle_{scanned_count}.js")
                with open(js_path, "w", encoding="utf-8") as handle:
                    handle.write(js_content)
                findings.extend(scan_file(js_path, src[:200]))
                scanned_count += 1
            except (ValueError, OSError, urllib.error.URLError, TimeoutError):
                # Avoid hiding scan limitations: record that a bundle could not be inspected.
                findings.append({"id": "SCAN-JS-UNAVAILABLE", "title": "JavaScript bundle could not be inspected",
                                 "severity": "LOW", "file": src[:200], "line": 1,
                                 "evidence": "Bundle fetch was blocked, failed, or exceeded limits.",
                                 "category": "SCAN_LIMIT", "secret_type": None, "confidence": "high"})
    return _result(final_url, "live_url", "completed", findings, scanned_count)


def scan_target(target: str) -> Dict[str, Any]:
    """Route a target to the appropriate scanner."""
    target = target.strip()
    if not target:
        return _result(target, "unknown", "failed", errors=["Target is empty."])
    if re.match(r"^https?://", target, re.IGNORECASE):
        return scan_live_url(target)
    if target.lower().endswith(".zip"):
        return scan_zip(target)
    if os.path.isfile(target):
        return scan_single_file(target)
    if os.path.isdir(target):
        return scan_project(target)
    # A host-like string is treated as a URL only when it looks like a hostname.
    if "." in target and not any(sep in target for sep in (os.sep, "/", "\\")):
        return scan_live_url(target)
    return _result(target, "unknown", "failed", errors=[f"Invalid or unreachable target: {target}"])


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    report = scan_target(target)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report["status"] == "completed":
        print(f"\n[+] Heuristic health score: {report['health_score']} / 100")
        return 0
    print("\n[!] Scan failed. No health score was calculated.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
