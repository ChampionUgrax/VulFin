{
  "scan_id": "sample-001",
  "findings": [
    {
      "id": "F-001",
      "fingerprint": "secret:src/config.js:api-key",
      "title": "Hardcoded API credential",
      "severity": "high",
      "category": "exposed_secret",
      "file": "src/config.js",
      "line": 18,
      "evidence": "apiKey = \"sk-••••\"",
      "recommendation": "Rotate the credential and remove it from source code.",
      "status": "open"
    }
  ]
}