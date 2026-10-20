# Security triage

87 scanner reports merged into **50 findings**: 1 critical, 19 high, 26 medium, 3 low; 1 suppressed; 50 new since the baseline.

**Gate: FAIL**, 20 new finding(s) at or above the threshold:
- CRITICAL pyjwt 1.7.1: PyJWT: Asymmetric-PEM detection bypass: whitespace/line-ending-mutated public keys skip the HS/asymmetric confusion guard
- HIGH pyjwt 1.7.1: Key confusion through non-blocklisted public key formats
- HIGH flask 2.2.2: Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header
- HIGH pyjwt 1.7.1: PyJWT: Public-key JWK accepted as HMAC secret enables forged HS256 tokens when mixed families are allowed
- HIGH pyjwt 1.7.1: PyJWT accepts unknown `crit` header extensions
- HIGH pyjwt 1.7.1: PyJWT: PyJWKClient follows redirects when fetching JWKS
- HIGH loan-api/app.py:16: Possible secret in source (Secret Keyword)
- HIGH loan-api/app.py:42: Hardcoded JWT secret or private key is used
- HIGH loan-api/app.py:82: Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
- HIGH loan-api/app.py:94: subprocess call with shell=True identified, security issue.
- HIGH loan-api/app.py:99: A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
- HIGH werkzeug 2.2.2: Werkzeug debugger vulnerable to remote execution when interacting with attacker controlled domain
- HIGH urllib3 1.26.5: Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API)
- HIGH werkzeug 2.2.2: High resource usage when parsing multipart form data with many fields
- HIGH urllib3 1.26.5: `Cookie` HTTP header isn't stripped on cross-origin redirects
- HIGH urllib3 1.26.5: urllib3 allows an unbounded number of links in the decompression chain
- HIGH urllib3 1.26.5: urllib3 streaming API improperly handles highly compressed data
- HIGH urllib3 1.26.5: urllib3: Sensitive headers forwarded across origins in proxied low-level redirects
- HIGH urllib3 1.26.5: urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory
- HIGH urllib3 1.26.5: urllib3: HTTPS proxy TLS configuration may be ignored or overridden
- Suppression expired 2026-09-30 (bandit:B113, owner loan-platform-team): it no longer suppresses anything.

## Findings by risk

| Risk | Severity | Where | What | Reachability | EPSS | KEV | Fix within | Found by |
|---|---|---|---|---|---|---|---|---|
| 10.08 | critical | pyjwt 1.7.1 | CVE-2026-102268: PyJWT: Asymmetric-PEM detection bypass: whitespace/line-ending-mutated pu | direct | 0.2% |  | 7 days | pip-audit |
| 7.38 | high | pyjwt 1.7.1 | CVE-2022-29217: Key confusion through non-blocklisted public key formats | direct | 1.4% |  | 30 days | pip-audit |
| 7.35 | high | flask 2.2.2 | CVE-2023-30861: Flask vulnerable to possible disclosure of permanent session cookie due to | direct | 1.3% |  | 30 days | pip-audit |
| 7.12 | high | pyjwt 1.7.1 | CVE-2026-48526: PyJWT: Public-key JWK accepted as HMAC secret enables forged HS256 tokens  | direct | 0.4% |  | 30 days | pip-audit |
| 7.08 | high | pyjwt 1.7.1 | CVE-2026-32597: PyJWT accepts unknown `crit` header extensions | direct | 0.3% |  | 30 days | pip-audit |
| 7.04 | high | pyjwt 1.7.1 | CVE-2026-102267: PyJWT: PyJWKClient follows redirects when fetching JWKS | direct | 0.2% |  | 30 days | pip-audit |
| 7 | high | loan-api/app.py:16 | Possible secret in source (Secret Keyword) | direct |  |  | 30 days | bandit, detect-secrets |
| 7 | high | loan-api/app.py:42 | Hardcoded JWT secret or private key is used | direct |  |  | 30 days | semgrep oss |
| 7 | high | loan-api/app.py:82 | Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_loa | direct |  |  | 30 days | bandit, semgrep oss |
| 7 | high | loan-api/app.py:94 | subprocess call with shell=True identified, security issue. | direct |  |  | 30 days | bandit, semgrep oss |
| 7 | high | loan-api/app.py:99 | A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and all | direct |  |  | 30 days | bandit, semgrep oss |
| 5.57 | high | werkzeug 2.2.2 | CVE-2024-34069: Werkzeug debugger vulnerable to remote execution when interacting with att | via flask | 3.4% |  | 30 days | pip-audit |
| 5.47 | high | urllib3 1.26.5 | CVE-2026-21441: Decompression-bomb safeguards bypassed when following HTTP redirects (stre | via requests | 2.9% |  | 30 days | pip-audit |
| 5.18 | high | werkzeug 2.2.2 | CVE-2023-25577: High resource usage when parsing multipart form data with many fields | via flask | 1.4% |  | 30 days | pip-audit |
| 5.17 | high | urllib3 1.26.5 | CVE-2023-43804: `Cookie` HTTP header isn't stripped on cross-origin redirects | via requests | 1.4% |  | 30 days | pip-audit |
| 5.03 | high | urllib3 1.26.5 | CVE-2025-66418: urllib3 allows an unbounded number of links in the decompression chain | via requests | 0.7% |  | 30 days | pip-audit |
| 5.03 | high | urllib3 1.26.5 | CVE-2025-66471: urllib3 streaming API improperly handles highly compressed data | via requests | 0.7% |  | 30 days | pip-audit |
| 4.97 | high | urllib3 1.26.5 | CVE-2026-44431: urllib3: Sensitive headers forwarded across origins in proxied low-level r | via requests | 0.3% |  | 30 days | pip-audit |
| 4.97 | high | urllib3 1.26.5 | CVE-2026-97689: urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-s | via requests | 0.3% |  | 30 days | pip-audit |
| 4.94 | high | urllib3 1.26.5 | CVE-2026-97687: urllib3: HTTPS proxy TLS configuration may be ignored or overridden | via requests | 0.2% |  | 30 days | pip-audit |
| 4.48 | medium | requests 2.28.0 | CVE-2023-32681: Unintended leak of Proxy-Authorization header in requests | direct | 3.0% |  | 90 days | pip-audit |
| 4.16 | medium | requests 2.28.0 | CVE-2024-47081: Requests vulnerable to .netrc credentials leak via malicious URLs | direct | 1.0% |  | 90 days | pip-audit |
| 4.07 | medium | pyjwt 1.7.1 | CVE-2026-101917: PyJWT: PyJWKClient still amplifies unauthenticated JWKS fetches on unknow | direct | 0.4% |  | 90 days | pip-audit |
| 4.05 | medium | requests 2.28.0 | CVE-2024-35195: Requests `Session` object does not verify requests after making first requ | direct | 0.3% |  | 90 days | pip-audit |
| 4.04 | medium | pyjwt 1.7.1 | CVE-2026-48522: PyJWKClient: missing scheme allowlist enables CVE-2024-21643-class SSRF +  | direct | 0.2% |  | 90 days | pip-audit |

## Remediation

5 upgrade(s) verified by the test suite in 13 test runs; 1 need a code change.

- **jinja2** 3.1.2 -> 3.1.6 (closes 5 advisories)
- **requests** 2.28.0 -> 2.33.0 (closes 4 advisories)
- **urllib3** 1.26.5 -> 2.8.0 (closes 10 advisories)
- **flask** 2.2.2 -> 3.1.3 (closes 2 advisories)
- **werkzeug** 2.2.2 -> 3.1.9 (closes 10 advisories)
- **pyjwt** 1.7.1 -> 2.14.0 breaks 2 test(s): tests/test_app.py::test_other_accounts_are_forbidden, tests/test_app.py::test_token_round_trip_and_account_access. First error: `E       AttributeError: 'str' object has no attribute 'decode'`

| Try | Packages | Result |
|---|---|---|
| current pins | (none) | pass |
| all at once | flask==3.1.3, jinja2==3.1.6, pyjwt==2.14.0, requests==2.33.0, urllib3==2.8.0, werkzeug==3.1.9 | fail: tests/test_app.py::test_other_accounts_are_forbidden, tests/test_app.py::test_token_round_trip_and_account_access |
| split | flask==3.1.3, jinja2==3.1.6, pyjwt==2.14.0 | fail: <install> |
| split | flask==3.1.3 | fail: <install> |
| split | jinja2==3.1.6, pyjwt==2.14.0 | fail: tests/test_app.py::test_other_accounts_are_forbidden, tests/test_app.py::test_token_round_trip_and_account_access |
| split | jinja2==3.1.6 | pass |
| split | pyjwt==2.14.0 | fail: tests/test_app.py::test_other_accounts_are_forbidden, tests/test_app.py::test_token_round_trip_and_account_access |
| split | requests==2.33.0, urllib3==2.8.0, werkzeug==3.1.9 | fail: tests/test_app.py |
| split | requests==2.33.0 | pass |
| split | urllib3==2.8.0, werkzeug==3.1.9 | fail: tests/test_app.py |
| split | urllib3==2.8.0 | pass |
| split | werkzeug==3.1.9 | fail: tests/test_app.py |
| flask with werkzeug | flask==3.1.3, werkzeug==3.1.9 | pass |
