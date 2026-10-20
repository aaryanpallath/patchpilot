"""One finding, whatever scanner reported it."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower is worse


@dataclass
class Finding:
    kind: str  # "code", "secret" or "dependency"
    title: str
    severity: str
    tools: list[str]
    rule_ids: list[str]
    confidence: str = "high"  # the scanner's confidence: high | medium | low
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    cwe: list[str] = field(default_factory=list)
    package: str | None = None
    version: str | None = None
    advisories: list[str] = field(default_factory=list)  # every id the advisory is known by (PYSEC, GHSA, CVE)
    fix_versions: list[str] = field(default_factory=list)
    # filled in by triage
    fingerprint: str = ""
    reachability: str = ""
    epss: float | None = None
    kev: bool = False
    risk: float = 0.0
    due_days: int | None = None
    status: str = "open"  # open | suppressed
    is_new: bool = True
    suppression: dict | None = None

    @property
    def cves(self) -> list[str]:
        return sorted(a for a in self.advisories if a.startswith("CVE-"))

    @property
    def where(self) -> str:
        if self.kind == "dependency":
            return f"{self.package} {self.version}"
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return asdict(self)


def worst(*severities: str) -> str:
    return min(severities, key=lambda s: RANK.get(s, len(SEVERITIES)))
