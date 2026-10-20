# patchpilot — Vulnerability Triage and Remediation for CI
Tech: Python, GitHub Actions, SARIF, Bandit, Semgrep, pip-audit, pytest
- Built a CI tool that merges Bandit, Semgrep, pip-audit and secret-scanner output, merging 87 reports into 50 findings, and ranks them by severity, EPSS exploit probability, CISA KEV status and whether the vulnerable package is imported.
- Automated dependency remediation verified by the service's own tests: a split search over upgrades shipped 5 of 6 vulnerable packages (closing 31 of 42 advisories), paired coupled Flask/Werkzeug upgrades, and isolated the breaking PyJWT change.
- Gated builds only on new findings using code-based fingerprints, with expiring, justified suppressions; uploads merged SARIF to GitHub code scanning.
