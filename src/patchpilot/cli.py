"""patchpilot: merge, prioritize and gate security findings, then fix what the tests allow.

    patchpilot --root demo --bandit demo/scans/bandit.json --sarif demo/scans/semgrep.sarif \\
        --pip-audit demo/scans/pip-audit.json --secrets demo/scans/detect-secrets.json:loan-api \\
        --requirements loan-api/requirements.txt --src loan-api --intel demo/intel.json \\
        --baseline demo/baseline.json --suppressions demo/suppressions.yaml --report report.md --remediate
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import ingest, reachability, report, triage
from .dedupe import dedupe
from .intel import Intel
from .remediate import UvTestRunner, plan, read_requirements, verify, write_requirements


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="patchpilot", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--root", default=".", help="repository root that scanner paths are relative to")
    p.add_argument("--bandit", action="append", default=[])
    p.add_argument("--sarif", action="append", default=[])
    p.add_argument("--pip-audit", dest="pip_audit")
    p.add_argument("--secrets", action="append", default=[], help="detect-secrets JSON, optionally FILE:PATH_PREFIX")
    p.add_argument("--requirements", required=True, help="pinned requirements file, relative to --root")
    p.add_argument("--src", required=True, help="service source directory, relative to --root")
    p.add_argument("--intel", default=".patchpilot-cache/intel.json", help="intelligence snapshot (read and updated)")
    p.add_argument("--offline", action="store_true", help="use only the snapshot; never touch the network")
    p.add_argument("--baseline", help="fingerprints of known findings; only new ones can fail the gate")
    p.add_argument("--write-baseline", help="write the current findings as the new baseline")
    p.add_argument("--suppressions")
    p.add_argument("--threshold", default="high", choices=["critical", "high", "medium", "low"])
    p.add_argument("--report", help="Markdown report path")
    p.add_argument("--sarif-out", help="merged findings as SARIF, for GitHub code scanning")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--remediate", action="store_true", help="plan upgrades and verify them with the test suite")
    p.add_argument("--requirements-out", help="where to write the upgraded requirements")
    a = p.parse_args(argv)

    root = Path(a.root)
    raw = []
    for f in a.bandit:
        raw += ingest.from_bandit(f, root)
    for f in a.sarif:
        raw += ingest.from_sarif(f, root)
    for spec in a.secrets:
        path, _, prefix = spec.partition(":")
        raw += ingest.from_detect_secrets(path, root, prefix)
    if a.pip_audit:
        raw += ingest.from_pip_audit(a.pip_audit, a.requirements)
    findings = dedupe(raw)

    req_path = root / a.requirements
    pins = read_requirements(req_path)
    req_lines = {
        ln.split("==")[0].strip().lower(): i for i, ln in enumerate(req_path.read_text().splitlines(), 1) if "==" in ln
    }
    for f in findings:
        if f.kind == "dependency":
            f.line = req_lines.get(f.package or "")

    intel = Intel(a.intel, offline=a.offline)
    try:
        reach = reachability.classify(pins, reachability.imported_modules(root / a.src), intel.requires)
        triage.enrich(findings, intel, reach)
        findings = triage.score(findings)
        expired = triage.apply_suppressions(findings, triage.load_suppressions(a.suppressions), date.today())
        baseline = set(json.loads(Path(a.baseline).read_text())) if a.baseline and Path(a.baseline).exists() else None
        triage.apply_baseline(findings, baseline)
        blocking = triage.gate(findings, a.threshold)

        remediation = None
        if a.remediate:
            upgrades, stuck = plan(findings, pins, intel)

            def coupled(u) -> list[str]:
                """Pinned packages that depend on u, or that u's target release depends on."""
                dependents = [d for d in pins if d != u.package and u.package in intel.requires(d, pins[d])]
                dependencies = [d for d in intel.requires(u.package, u.target) if d in pins]
                return sorted({*dependents, *dependencies})

            def latest(pkg: str) -> str:
                return intel.releases(pkg)[-1]

            remediation = verify(pins, upgrades, UvTestRunner(root / a.src), coupled, latest)
            remediation.no_fix_available = stuck
            if a.requirements_out:
                Path(a.requirements_out).write_text(write_requirements(req_path, remediation.pins, remediation.shipped))
    finally:
        intel.save()

    md = report.markdown(findings, len(raw), blocking, expired, remediation)
    if a.report:
        Path(a.report).write_text(md)
    else:
        print(md)
    if a.sarif_out:
        Path(a.sarif_out).write_text(report.sarif(findings))
    if a.json_out:
        out = {
            "raw_reports": len(raw),
            "findings": [f.to_dict() for f in findings],
            "blocking": [f.fingerprint for f in blocking],
            "expired_suppressions": [str(e) for e in expired],
        }
        if remediation:
            out["remediation"] = {
                "shipped": [u.__dict__ for u in remediation.shipped],
                "needs_code_change": [
                    {"upgrade": u.__dict__, "failed": r.failed, "detail": r.detail}
                    for u, r in remediation.needs_code_change
                ],
                "no_fix_available": remediation.no_fix_available,
                "runs": remediation.runs,
            }
        Path(a.json_out).write_text(json.dumps(out, indent=1, default=str) + "\n")
    if a.write_baseline:
        Path(a.write_baseline).write_text(json.dumps(sorted(f.fingerprint for f in findings), indent=1) + "\n")
    print(f"{len(raw)} reports -> {len(findings)} findings; gate {'FAIL' if blocking else 'PASS'}", file=sys.stderr)
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
