"""Vulnerability intelligence: OSV (advisory details and which versions are affected), PyPI (releases and
dependencies), FIRST EPSS (probability of exploitation in the next 30 days) and the CISA Known Exploited
Vulnerabilities catalog.

Every answer is cached in one JSON snapshot. Committing the snapshot makes a triage run reproducible and lets
tests and CI run offline."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class OfflineMiss(KeyError):
    pass


class Intel:
    def __init__(self, snapshot: str | Path, offline: bool = False):
        self.path = Path(snapshot)
        self.offline = offline
        self.data: dict[str, Any] = json.loads(self.path.read_text()) if self.path.exists() else {}
        self._dirty = False

    def save(self) -> None:
        if self._dirty:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=1, sort_keys=True) + "\n")
            self._dirty = False

    def _get(self, key: str, url: str, body: dict | None = None, keep: Any = None) -> Any:
        """Fetch once and cache only what `keep` extracts, so the snapshot stays small."""
        if key in self.data:
            return self.data[key]
        if self.offline:
            raise OfflineMiss(key)
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body else None,
            headers={"User-Agent": "patchpilot", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            value = json.loads(r.read())
        value = keep(value) if keep else value
        self.data[key] = value
        self._dirty = True
        return value

    # ------------------------------------------------------------------ OSV
    def advisory(self, advisory_ids: list[str]) -> dict[str, str]:
        """GitHub's severity label and one-line summary, found through whichever alias is a GHSA id."""
        for a in sorted(advisory_ids):
            if a.startswith("GHSA-"):
                v = self._get(
                    f"osv2:{a}",
                    f"https://api.osv.dev/v1/vulns/{a}",
                    keep=lambda v: {
                        "severity": (v.get("database_specific") or {}).get("severity"),
                        "summary": v.get("summary"),
                    },
                )
                if v.get("severity"):
                    label = v["severity"]
                    return {"severity": {"MODERATE": "medium"}.get(label, label.lower()), "summary": v.get("summary")}
        return {}

    def affected_by(self, package: str, version: str) -> set[str]:
        """Every advisory id (with aliases) that OSV says affects this exact version."""
        ids = self._get(
            f"osvq:{package}=={version}",
            "https://api.osv.dev/v1/query",
            {"package": {"name": package, "ecosystem": "PyPI"}, "version": version},
            keep=lambda r: sorted({i for v in r.get("vulns", []) for i in (v["id"], *v.get("aliases", []))}),
        )
        return set(ids)

    # ------------------------------------------------------------------ PyPI
    def releases(self, package: str) -> list[str]:
        def usable(r: dict) -> list[str]:
            out = []
            for v, files in r["releases"].items():
                try:
                    pv = Version(v)
                except InvalidVersion:
                    continue
                if files and not pv.is_prerelease and not all(f.get("yanked") for f in files):
                    out.append(v)
            return sorted(out, key=Version)

        return self._get(f"pypi:{package}", f"https://pypi.org/pypi/{package}/json", keep=usable)

    def requires(self, package: str, version: str) -> list[str]:
        """Names of the packages this release depends on (ignoring extras-only requirements)."""
        reqs = self._get(
            f"pypi:{package}=={version}",
            f"https://pypi.org/pypi/{package}/{version}/json",
            keep=lambda r: r["info"].get("requires_dist") or [],
        )
        names = []
        for req in reqs:
            if "extra ==" in req:
                continue
            name = req.split(";")[0].split("[")[0]
            for sep in "<>=!~ (":
                name = name.split(sep)[0]
            names.append(name.strip().lower())
        return names

    # ------------------------------------------------------------------ exploitation
    def epss(self, cves: list[str]) -> dict[str, float]:
        out = {}
        for c in cves:
            score = self._get(
                f"epss:{c}",
                f"https://api.first.org/data/v1/epss?cve={c}",
                keep=lambda r: float(r["data"][0]["epss"]) if r.get("data") else None,
            )
            if score is not None:
                out[c] = score
        return out

    def kev(self) -> set[str]:
        if "kev" not in self.data:
            if self.offline:
                raise OfflineMiss("kev")
            with urllib.request.urlopen(
                urllib.request.Request(KEV_URL, headers={"User-Agent": "patchpilot"}), timeout=60
            ) as r:
                catalog = json.loads(r.read())
            self.data["kev"] = {
                "catalogVersion": catalog.get("catalogVersion"),
                "cves": sorted(v["cveID"] for v in catalog["vulnerabilities"]),
            }
            self._dirty = True
        return set(self.data["kev"]["cves"])
