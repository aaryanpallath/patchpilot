"""Turn merged findings into a prioritized, tracked backlog and a CI decision.

Risk = severity weight x exploitation factor x reachability factor:
  severity:      critical 10, high 7, medium 4, low 1
  exploitation:  x (1 + 4 * EPSS), and x 2 if the CVE is in CISA's Known Exploited Vulnerabilities catalog
  reachability:  direct 1.0, transitive 0.7, unused 0.4 (code and secret findings are always direct)
  confidence:    x 0.6 when the only scanner reporting it says its confidence is low
Fix-by deadlines: critical 7 days, high 30, medium 90, low 180; anything known to be exploited, 7.
"""

from __future__ import annotations

import contextlib
import hashlib
from datetime import date

import yaml

from .intel import Intel, OfflineMiss
from .models import RANK, Finding

WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def fingerprint(f: Finding) -> str:
    """Stable across line moves and scanner versions: the file and the offending code for code findings, the package
    and its advisory for dependencies."""
    if f.kind == "dependency":
        key = f"dep|{f.package}|{sorted(f.cves or f.advisories)[0]}"
    else:
        key = f"{f.kind}|{f.file}|{' '.join((f.snippet or '').split())}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def enrich(findings: list[Finding], intel: Intel, reach: dict[str, str]) -> None:
    kev = intel.kev()
    for f in findings:
        f.fingerprint = fingerprint(f)
        if f.kind != "dependency":
            f.reachability = "direct"
            continue
        with contextlib.suppress(OfflineMiss):
            info = intel.advisory(f.advisories)
            f.severity = info.get("severity") or f.severity
            f.title = info.get("summary") or f.title
        f.reachability = reach.get(f.package or "", "unused")
        scores = intel.epss(f.cves)
        f.epss = max(scores.values()) if scores else None
        f.kev = any(c in kev for c in f.cves)


def score(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        reach = 1.0 if f.reachability == "direct" else 0.7 if f.reachability.startswith("via") else 0.4
        conf = 0.6 if f.confidence == "low" else 1.0
        f.risk = round(WEIGHT[f.severity] * (1 + 4 * (f.epss or 0)) * (2 if f.kev else 1) * reach * conf, 2)
        f.due_days = 7 if f.kev else SLA_DAYS[f.severity]
    return sorted(findings, key=lambda f: (-f.risk, RANK[f.severity], f.where))


def load_suppressions(path: str | None) -> list[dict]:
    if not path:
        return []
    with open(path) as fh:
        entries = yaml.safe_load(fh) or []
    for e in entries:
        missing = [k for k in ("reason", "owner", "expires") if not e.get(k)]
        if missing or not (e.get("fingerprint") or e.get("rule")):
            raise ValueError(f"suppression {e} needs fingerprint or rule, plus reason, owner and expires")
    return entries


def apply_suppressions(findings: list[Finding], entries: list[dict], today: date) -> list[dict]:
    """Suppress matching findings; return the suppressions that have expired (they no longer suppress)."""
    expired = []
    for e in entries:
        exp = e["expires"] if isinstance(e["expires"], date) else date.fromisoformat(str(e["expires"]))
        if exp < today:
            expired.append(e)
            continue
        for f in findings:
            match_fp = e.get("fingerprint") == f.fingerprint
            match_rule = e.get("rule") in f.rule_ids and (not e.get("path") or e["path"] == f.file)
            if match_fp or (e.get("rule") and match_rule):
                f.status, f.suppression = "suppressed", e
    return expired


def apply_baseline(findings: list[Finding], baseline: set[str] | None) -> None:
    for f in findings:
        f.is_new = baseline is None or f.fingerprint not in baseline


def gate(findings: list[Finding], threshold: str = "high") -> list[Finding]:
    """Findings that should fail the build: new since the baseline, not suppressed, at or above the threshold."""
    return [f for f in findings if f.is_new and f.status == "open" and RANK[f.severity] <= RANK[threshold]]
