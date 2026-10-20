# patchpilot — Vulnerability Triage and Test-Verified Remediation

Security scanners are easy to add to a pipeline and hard to act on. Each one reports the same problem in its own
format, dependency audits list one advisory under three ids, and nothing tells a team which of 87 reports to fix
first, which ones are new, or which upgrades are safe to ship. patchpilot sits after the scanners in CI and does
four things:

1. **Merges** Bandit, SARIF (Semgrep or any SARIF tool), pip-audit and detect-secrets output into one list, so each
   problem appears once.
2. **Prioritizes** each finding by severity, the probability of exploitation (FIRST EPSS), CISA's Known Exploited
   Vulnerabilities catalog, and whether the vulnerable package is actually imported. Each gets a fix-by deadline.
3. **Gates** the build only on findings that are new since a baseline, with suppressions that need a reason, an
   owner and an expiry date.
4. **Remediates** dependencies: it picks the smallest release clear of every open advisory, then lets the service's
   own test suite decide which upgrades ship.

## On the demo service

`demo/loan-api` is a small Flask loan-servicing API (payment quotes, amortization schedules, account lookup) with
the problems older services accumulate: pinned 2022-era dependencies, a hardcoded signing key, `yaml.load`, a SQL
query built from strings, and `shell=True`. It has a test suite. The real scanner output is in `demo/scans` (advisory descriptions trimmed from the pip-audit file, since one quotes a sample private key from a PyJWT advisory), and
the full report is `demo/report.md`.

| | |
|---|---|
| Scanner reports | 87 (Bandit 7, Semgrep 6, detect-secrets 1, pip-audit 73) |
| After merging | **50 findings**: 8 in code, 42 dependency advisories |
| Biggest merge | one `shell=True` line reported by 4 rules from 2 scanners |
| Dependency advisories closed by verified upgrades | **31 of 42**, across 5 packages |
| Left for a person | PyJWT 1.x -> 2.x (11 advisories): breaks 2 tests, with the error attached |

**How remediation played out** (13 runs of the service's tests, about 90 seconds; full log in `demo/report.md`):

- **Current pins pass.** Upgrading all six vulnerable packages at once fails.
- **Splitting the batch** ships Jinja2 3.1.6, requests 2.33.0 and urllib3 2.8.0. It isolates three failures:
  - PyJWT 2.14 breaks 2 tests: `AttributeError: 'str' object has no attribute 'decode'`. PyJWT 2 returns tokens
    as strings, so the code has to change.
  - Werkzeug 3.1.9 alone breaks the old Flask.
  - Flask 3.1.3 alone can't even install next to the old Werkzeug.
- **Retrying coupled packages together**, in either direction of the dependency, ships Flask 3.1.3 and Werkzeug
  3.1.9 as one change.
- **The output** is a rewritten `requirements.txt` with a comment per upgrade (`demo/requirements.patchpilot.txt`),
  plus the one item that needs a developer.

**Prioritization in the report.** A critical PyJWT key-confusion advisory leads, because PyJWT is imported directly.
Werkzeug's debugger RCE has the highest EPSS of the set (3.4%), but it ranks lower because Werkzeug is only reached
through Flask. None of the demo's CVEs are in the KEV catalog; if one were, its deadline would drop to 7 days and
its score would double. Scores and deadlines follow a formula written out in `src/patchpilot/triage.py`.

## Is split search worth it?

Finding the largest passing set of upgrades is a group-testing problem. `bench/strategies.py` compares patchpilot's
recursive split against upgrading one package at a time (n runs plus one combined run), over 400 random cases each:

| Upgrades | Breaking | One at a time | Split search (mean / worst) |
|---|---|---|---|
| 20 | 1 | 21 | 9.9 / 11 |
| 20 | 3 | 21 | 19.3 / 25 |
| 50 | 1 | 51 | 12.4 / 13 |
| 50 | 5 | 51 | 37.2 / 45 |
| 6 | 3 | 7 | 10.0 / 11 |

Split search wins when breaking upgrades are a small fraction of the batch, the usual case for a large backlog of
patch releases. It loses when most of a small batch breaks. The demo is that case: one at a time would have taken
about 8 runs instead of 13. A team with mostly major-version upgrades should test them individually.

## Usage

```bash
uv sync
patchpilot --root demo \
  --bandit demo/scans/bandit.json --sarif demo/scans/semgrep.sarif \
  --pip-audit demo/scans/pip-audit.json --secrets demo/scans/detect-secrets.json:loan-api \
  --requirements loan-api/requirements.txt --src loan-api \
  --intel demo/intel.json --baseline demo/baseline.json --suppressions demo/suppressions.yaml \
  --report report.md --sarif-out patchpilot.sarif --remediate --requirements-out requirements.new.txt
```

- Exit code 1 means the gate failed: a new, unsuppressed finding at or above `--threshold` (default high).
- `--write-baseline` records the current findings. Fingerprints use the offending code, not its line number, so
  moving code doesn't create "new" findings.
- `--intel` is a JSON snapshot of every OSV, PyPI, EPSS and KEV answer used. Commit it and `--offline` reproduces a
  run exactly, which is how the tests run.
- `--sarif-out` writes the merged findings for GitHub code scanning.

CI (`.github/workflows/ci.yml`) runs the tests, then the full pipeline on the demo: live scanners, patchpilot,
SARIF upload to code scanning, and test-verified remediation. The live gate is informational, since an advisory
published after the baseline should fail it.

## Limitations

- Python dependencies only (PyPI and OSV); other ecosystems would need their own release and dependency lookups.
- Coupled upgrades are found through declared dependencies. A break with no dependency link between the packages
  is reported as needing a code change.
- Reachability works at the package level (imported or not), not at the level of the vulnerable function.
- The remediation is only as good as the test suite. An upgrade that breaks untested behavior will pass.

## License and AI disclosure

MIT (see `LICENSE`). Built with help from Claude (Anthropic) via Claude Code; I reviewed, tested and verified the
code and results.
