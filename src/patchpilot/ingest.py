"""Readers for scanner output: Bandit JSON, SARIF (Semgrep and others), pip-audit JSON, detect-secrets JSON.

Paths are normalized to be relative to the repository root, and code findings carry the source line itself, which
is what fingerprints are built from (line numbers move; the offending code usually doesn't)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding

_BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def _source_line(root: Path, file: str, line: int) -> str:
    try:
        return (root / file).read_text().splitlines()[line - 1].strip()
    except (OSError, IndexError):
        return ""


def _rel(path: str, prefix: str = "") -> str:
    p = Path(prefix) / path if prefix else Path(path)
    return p.as_posix().removeprefix("./")


def from_bandit(path: str | Path, root: str | Path, prefix: str = "") -> list[Finding]:
    root = Path(root)
    out = []
    for r in json.loads(Path(path).read_text())["results"]:
        file = _rel(r["filename"], prefix)
        # low confidence lowers the risk score, not the severity: B608 (SQL built from strings) is low-confidence
        # but, when right, it is an injection
        out.append(
            Finding(
                kind="code",
                title=r["issue_text"],
                severity=_BANDIT_SEVERITY[r["issue_severity"]],
                confidence=r["issue_confidence"].lower(),
                tools=["bandit"],
                rule_ids=[f"bandit:{r['test_id']}"],
                file=file,
                line=r["line_number"],
                snippet=_source_line(root, file, r["line_number"]),
                cwe=[f"CWE-{r['issue_cwe']['id']}"] if r.get("issue_cwe") else [],
            )
        )
    return out


def from_sarif(path: str | Path, root: str | Path, prefix: str = "") -> list[Finding]:
    root = Path(root)
    out = []
    for run in json.loads(Path(path).read_text())["runs"]:
        tool = run["tool"]["driver"]["name"].lower()
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res["ruleId"], {})
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            loc = res["locations"][0]["physicalLocation"]
            file = _rel(loc["artifactLocation"]["uri"], prefix)
            line = loc["region"]["startLine"]
            tags = rule.get("properties", {}).get("tags", [])
            cwe = sorted({m.group(0) for t in tags for m in [re.match(r"CWE-\d+", t)] if m})
            out.append(
                Finding(
                    kind="code",
                    title=res["message"]["text"].split(". ")[0],
                    severity=_SARIF_LEVEL.get(level, "medium"),
                    tools=[tool],
                    rule_ids=[f"{tool}:{res['ruleId'].split('.')[-1]}"],
                    file=file,
                    line=line,
                    snippet=_source_line(root, file, line),
                    cwe=cwe,
                )
            )
    return out


def from_pip_audit(path: str | Path, requirements: str) -> list[Finding]:
    out = []
    for dep in json.loads(Path(path).read_text())["dependencies"]:
        for v in dep.get("vulns", []):
            out.append(
                Finding(
                    kind="dependency",
                    title=v.get("description", "").split(". ")[0][:160] or v["id"],
                    severity="medium",  # pip-audit reports no severity; triage looks it up
                    tools=["pip-audit"],
                    rule_ids=[v["id"]],
                    file=requirements,
                    package=dep["name"].lower(),
                    version=dep["version"],
                    advisories=sorted({v["id"], *v.get("aliases", [])}),
                    fix_versions=v.get("fix_versions", []),
                )
            )
    return out


def from_detect_secrets(path: str | Path, root: str | Path, prefix: str = "") -> list[Finding]:
    root = Path(root)
    out = []
    for _, hits in json.loads(Path(path).read_text())["results"].items():
        for h in hits:
            file = _rel(h["filename"], prefix)
            out.append(
                Finding(
                    kind="secret",
                    title=f"Possible secret in source ({h['type']})",
                    severity="high",
                    tools=["detect-secrets"],
                    rule_ids=[f"detect-secrets:{h['type']}"],
                    file=file,
                    line=h["line_number"],
                    snippet=_source_line(root, file, h["line_number"]),
                    cwe=["CWE-798"],
                )
            )
    return out
