"""Merge duplicate reports.

Code: reports on the same file and line are one problem, however many scanners or rules flagged it. A secret
finding absorbs code findings on its line (Bandit's hardcoded-password rule and detect-secrets see the same key).
Dependencies: one advisory is published under several ids (PYSEC, GHSA, CVE), so reports for a package are merged
when their id sets overlap, transitively."""

from __future__ import annotations

from .models import Finding, worst


def _merge_into(a: Finding, b: Finding) -> None:
    a.severity = worst(a.severity, b.severity)
    order = ("high", "medium", "low")
    a.confidence = min(a.confidence, b.confidence, key=order.index)  # agreement between scanners: keep the strongest
    a.tools = sorted({*a.tools, *b.tools})
    a.rule_ids = sorted({*a.rule_ids, *b.rule_ids})
    a.cwe = sorted({*a.cwe, *b.cwe})
    a.advisories = sorted({*a.advisories, *b.advisories})
    a.fix_versions = sorted({*a.fix_versions, *b.fix_versions})
    if b.kind == "secret":
        a.kind, a.title = "secret", b.title


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_line: dict[tuple[str, int], Finding] = {}
    deps: list[Finding] = []
    for f in findings:
        if f.kind == "dependency":
            deps.append(f)
            continue
        key = (f.file or "", f.line or 0)
        if key in by_line:
            _merge_into(by_line[key], f)
        else:
            by_line[key] = Finding(**{**f.__dict__})
    merged_deps: list[Finding] = []
    for f in deps:
        hits = [m for m in merged_deps if m.package == f.package and set(m.advisories) & set(f.advisories)]
        if not hits:
            merged_deps.append(Finding(**{**f.__dict__}))
            continue
        keep = hits[0]
        _merge_into(keep, f)
        for other in hits[1:]:  # f bridged two groups: fold them together
            _merge_into(keep, other)
            merged_deps.remove(other)
    return list(by_line.values()) + merged_deps
