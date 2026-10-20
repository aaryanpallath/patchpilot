"""Markdown report for people, SARIF for GitHub code scanning, JSON for everything else."""

from __future__ import annotations

import json
from collections import Counter

from .models import SEVERITIES, Finding
from .remediate import Remediation


def markdown(
    findings: list[Finding],
    raw_count: int,
    blocking: list[Finding],
    expired: list[dict],
    remediation: Remediation | None = None,
    limit: int = 25,
) -> str:
    sev = Counter(f.severity for f in findings if f.status == "open")
    out = ["# Security triage", ""]
    out.append(
        f"{raw_count} scanner reports merged into **{len(findings)} findings**: "
        + ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s])
        + f"; {sum(f.status == 'suppressed' for f in findings)} suppressed; "
        + f"{sum(f.is_new for f in findings)} new since the baseline."
    )
    out.append("")
    if blocking:
        out.append(f"**Gate: FAIL**, {len(blocking)} new finding(s) at or above the threshold:")
        out += [f"- {f.severity.upper()} {f.where}: {f.title}" for f in blocking]
    else:
        out.append("**Gate: PASS**, no new findings at or above the threshold.")
    for e in expired:
        out.append(
            f"- Suppression expired {e['expires']} ({e.get('rule') or e.get('fingerprint')}, owner "
            f"{e['owner']}): it no longer suppresses anything."
        )
    out += [
        "",
        "## Findings by risk",
        "",
        "| Risk | Severity | Where | What | Reachability | EPSS | KEV | Fix within | Found by |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for f in [f for f in findings if f.status == "open"][:limit]:
        what = f.title if f.kind != "dependency" else f"{', '.join(f.cves[:2]) or f.advisories[0]}: {f.title}"
        epss = f"{f.epss:.1%}" if f.epss is not None else ""
        out.append(
            f"| {f.risk:g} | {f.severity} | {f.where} | {what[:90].replace('|', '/')} | {f.reachability} | "
            f"{epss} | {'yes' if f.kev else ''} | {f.due_days} days | {', '.join(f.tools)} |"
        )
    if remediation:
        r = remediation
        out += [
            "",
            "## Remediation",
            "",
            f"{len(r.shipped)} upgrade(s) verified by the test suite in {len(r.runs)} test runs; "
            f"{len(r.needs_code_change)} need a code change.",
            "",
        ]
        for u in r.shipped:
            why = f"needed by the {u.companion_of} upgrade" if u.companion_of else f"closes {len(u.fixes)} advisories"
            out.append(f"- **{u.package}** {u.current} -> {u.target} ({why})")
        for u, res in r.needs_code_change:
            out.append(
                f"- **{u.package}** {u.current} -> {u.target} breaks {len(res.failed)} test(s): "
                + ", ".join(res.failed[:4])
                + (f". First error: `{res.detail}`" if res.detail else "")
            )
        out += ["", "| Try | Packages | Result |", "|---|---|---|"]
        for run in r.runs:
            out.append(
                f"| {run['try']} | {', '.join(run['packages']) or '(none)'} | "
                f"{'pass' if run['passed'] else 'fail: ' + ', '.join(run['failed'][:2])} |"
            )
    return "\n".join(out) + "\n"


def sarif(findings: list[Finding]) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results = []
    for f in findings:
        if f.status != "open":
            continue
        results.append(
            {
                "ruleId": f.rule_ids[0],
                "level": level[f.severity],
                "message": {
                    "text": f"{f.title} (risk {f.risk:g}, fix within {f.due_days} days; "
                    f"reported by {', '.join(f.tools)})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file or "requirements.txt"},
                            "region": {"startLine": f.line or 1},
                        }
                    }
                ],
                "partialFingerprints": {"patchpilot/v1": f.fingerprint},
                "properties": {
                    "security-severity": str({"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0}[f.severity])
                },
            }
        )
    rules = sorted({r["ruleId"] for r in results})
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "patchpilot", "rules": [{"id": r} for r in rules]}}, "results": results}],
    }
    return json.dumps(doc, indent=1)
