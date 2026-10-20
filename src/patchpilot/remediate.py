"""Test-verified dependency remediation.

1. For each vulnerable package, the target is the smallest release that OSV says is affected by none of the
   package's open advisories (checked per version, not taken on trust from each advisory's fix list).
2. The service's own tests decide what ships. All upgrades are tried at once; if the tests fail, the set is split
   in half and each half is tried on top of what has already passed, recursively. Upgrades that pass ship; a single
   upgrade that fails is isolated with the tests it breaks.
3. An isolated failure is retried together with the pinned packages it is coupled to, in either direction: its
   dependents (a new Werkzeug breaks the old Flask) and its dependencies (a new Flask cannot install with the old
   Werkzeug). Coupled packages that are themselves being upgraded use their safe target; others move to their
   latest release. If the group passes it ships together; if not, the upgrade needs a code change and the report
   says which tests broke.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from packaging.version import Version

from .intel import Intel
from .models import Finding


@dataclass
class Upgrade:
    package: str
    current: str
    target: str
    fixes: list[str]  # CVE (or other) ids this upgrade closes
    companion_of: str | None = None


@dataclass
class RunResult:
    passed: bool
    failed: list[str] = field(default_factory=list)
    detail: str = ""
    seconds: float = 0.0


@dataclass
class Remediation:
    shipped: list[Upgrade]
    needs_code_change: list[tuple[Upgrade, RunResult]]
    no_fix_available: list[str]
    runs: list[dict]
    pins: dict[str, str]


def read_requirements(path: str | Path) -> dict[str, str]:
    pins = {}
    for line in Path(path).read_text().splitlines():
        line = line.split("#")[0].strip()
        if "==" in line:
            name, ver = line.split("==", 1)
            pins[name.strip().lower()] = ver.strip()
    return pins


def write_requirements(original: str | Path, pins: dict[str, str], upgrades: list[Upgrade]) -> str:
    notes = {u.package: u for u in upgrades}
    out = []
    for line in Path(original).read_text().splitlines():
        body = line.split("#")[0].strip()
        if "==" in body:
            name = body.split("==", 1)[0].strip()
            key = name.lower()
            if key in notes:
                u = notes[key]
                why = f"companion of {u.companion_of}" if u.companion_of else "fixes " + ", ".join(u.fixes[:4])
                more = f" +{len(u.fixes) - 4} more" if len(u.fixes) > 4 and not u.companion_of else ""
                out.append(f"{name}=={pins[key]}  # patchpilot: {u.current} -> {u.target}, {why}{more}")
                continue
        out.append(line)
    return "\n".join(out) + "\n"


def safe_target(intel: Intel, package: str, current: str, advisories: set[str]) -> str | None:
    """Smallest release newer than `current` that is affected by none of `advisories`."""
    for v in intel.releases(package):
        if Version(v) > Version(current) and not (intel.affected_by(package, v) & advisories):
            return v
    return None


def plan(findings: list[Finding], pins: dict[str, str], intel: Intel) -> tuple[list[Upgrade], list[str]]:
    by_pkg: dict[str, list[Finding]] = {}
    for f in findings:
        if f.kind == "dependency" and f.package in pins and f.status == "open":
            by_pkg.setdefault(f.package, []).append(f)
    ups, stuck = [], []
    for pkg, fs in sorted(by_pkg.items()):
        advisories = {a for f in fs for a in f.advisories}
        target = safe_target(intel, pkg, pins[pkg], advisories)
        fixes = sorted({(f.cves or f.advisories)[0] for f in fs})
        if target:
            ups.append(Upgrade(pkg, pins[pkg], target, fixes))
        else:
            stuck.append(pkg)
    return ups, stuck


class UvTestRunner:
    """Builds a fresh virtual environment with uv for each set of pins and runs the project's pytest suite.
    Results are memoized by the pin set, so no combination is ever tested twice."""

    def __init__(self, project_dir: str | Path, python: str = "3.11", extra: tuple[str, ...] = ("pytest",)):
        self.project_dir = Path(project_dir).resolve()
        self.python = python
        self.extra = extra
        self._memo: dict[str, RunResult] = {}

    def __call__(self, pins: dict[str, str]) -> RunResult:
        key = hashlib.sha256(repr(sorted(pins.items())).encode()).hexdigest()
        if key in self._memo:
            return self._memo[key]
        t0 = time.monotonic()
        venv = Path(tempfile.mkdtemp(prefix="patchpilot-")) / "venv"
        try:
            subprocess.run(["uv", "venv", "-q", "--python", self.python, str(venv)], check=True, capture_output=True)
            py = str(venv / "bin" / "python")
            reqs = [f"{p}=={v}" for p, v in sorted(pins.items())] + list(self.extra)
            inst = subprocess.run(["uv", "pip", "install", "-q", "--python", py, *reqs], capture_output=True, text=True)
            if inst.returncode != 0:
                res = RunResult(False, ["<install>"], inst.stderr.strip().splitlines()[-1] if inst.stderr else "")
            else:
                t = subprocess.run(
                    [py, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", "tests"],
                    cwd=self.project_dir,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                failed = sorted(set(re.findall(r"^(?:FAILED|ERROR) (\S+)", t.stdout, re.M)))
                lines = [ln for ln in t.stdout.splitlines() if re.search(r"Error|error:", ln)]
                res = RunResult(t.returncode == 0, failed, lines[0].strip()[:300] if lines else "")
        finally:
            shutil.rmtree(venv.parent, ignore_errors=True)
        res.seconds = round(time.monotonic() - t0, 1)
        self._memo[key] = res
        return res


def verify(
    base: dict[str, str],
    upgrades: list[Upgrade],
    run: Callable[[dict[str, str]], RunResult],
    coupled: Callable[[Upgrade], list[str]] | None = None,
    latest: Callable[[str], str] | None = None,
) -> Remediation:
    runs: list[dict] = []
    accepted: dict[str, Upgrade] = {}

    def pins_with(group: list[Upgrade]) -> dict[str, str]:
        return {**base, **{u.package: u.target for u in accepted.values()}, **{u.package: u.target for u in group}}

    def test(group: list[Upgrade], label: str) -> RunResult:
        r = run(pins_with(group))
        runs.append(
            {
                "try": label,
                "packages": [f"{u.package}=={u.target}" for u in group],
                "passed": r.passed,
                "failed": r.failed[:5],
                "seconds": r.seconds,
            }
        )
        return r

    before = run(base)
    runs.append(
        {
            "try": "current pins",
            "packages": [],
            "passed": before.passed,
            "failed": before.failed[:5],
            "seconds": before.seconds,
        }
    )
    if not before.passed:
        raise RuntimeError(f"tests fail before any upgrade: {before.failed[:5]} {before.detail}")

    isolated: list[tuple[Upgrade, RunResult]] = []

    def search(group: list[Upgrade], label: str) -> None:
        if not group:
            return
        r = test(group, label)
        if r.passed:
            accepted.update({u.package: u for u in group})
        elif len(group) == 1:
            isolated.append((group[0], r))
        else:
            mid = len(group) // 2
            search(group[:mid], "split")
            search(group[mid:], "split")

    search(upgrades, "all at once")

    needs_change: list[tuple[Upgrade, RunResult]] = []
    planned = {u.package: u for u, _ in isolated}
    for u, r in isolated:
        if u.package in accepted:  # already shipped as part of another package's group
            continue
        companions = []
        for dep in coupled(u) if coupled else []:
            if dep not in base or dep in accepted or dep == u.package:
                continue
            if dep in planned:
                companions.append(planned[dep])
            elif latest and Version(latest(dep)) > Version(base[dep]):
                companions.append(Upgrade(dep, base[dep], latest(dep), [], companion_of=u.package))
        if companions:
            r2 = test([u, *companions], f"{u.package} with " + ", ".join(c.package for c in companions))
            if r2.passed:
                accepted.update({x.package: x for x in (u, *companions)})
                continue
            r = r2
        needs_change.append((u, r))
    return Remediation(list(accepted.values()), needs_change, [], runs, pins_with([]))
