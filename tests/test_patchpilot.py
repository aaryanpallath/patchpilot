from datetime import date
from pathlib import Path

import pytest

from patchpilot import ingest, reachability, triage
from patchpilot.cli import main
from patchpilot.dedupe import dedupe
from patchpilot.intel import Intel, OfflineMiss
from patchpilot.models import Finding
from patchpilot.remediate import RunResult, Upgrade, read_requirements, safe_target, verify, write_requirements

DEMO = Path(__file__).resolve().parent.parent / "demo"
SCANS = DEMO / "scans"


def raw_reports():
    return (
        ingest.from_bandit(SCANS / "bandit.json", DEMO)
        + ingest.from_sarif(SCANS / "semgrep.sarif", DEMO)
        + ingest.from_detect_secrets(SCANS / "detect-secrets.json", DEMO, "loan-api")
        + ingest.from_pip_audit(SCANS / "pip-audit.json", "loan-api/requirements.txt")
    )


# ------------------------------------------------------------------------------------------------ ingest and merge
def test_ingest_reads_every_scanner_and_carries_the_source_line():
    raw = raw_reports()
    assert len(raw) == 87
    assert {t for f in raw for t in f.tools} == {"bandit", "semgrep oss", "detect-secrets", "pip-audit"}
    yaml_hit = next(f for f in raw if f.rule_ids == ["bandit:B506"])
    assert yaml_hit.snippet.startswith("config = yaml.load(request.data")


def test_dedupe_merges_same_line_reports_and_advisory_aliases():
    findings = dedupe(raw_reports())
    code = [f for f in findings if f.kind != "dependency"]
    deps = [f for f in findings if f.kind == "dependency"]
    assert (len(code), len(deps)) == (8, 42)
    shell = next(f for f in code if f.line == 94)
    assert len(shell.rule_ids) == 4 and shell.tools == ["bandit", "semgrep oss"]
    secret = next(f for f in code if f.line == 16)
    assert secret.kind == "secret" and secret.tools == ["bandit", "detect-secrets"]
    for d in deps:  # no advisory id appears in two findings for the same package
        others = [o for o in deps if o is not d and o.package == d.package]
        assert not any(set(d.advisories) & set(o.advisories) for o in others)


def test_low_confidence_lowers_risk_not_severity():
    sql = next(f for f in dedupe(raw_reports()) if f.rule_ids == ["bandit:B608"])
    assert sql.severity == "medium"
    timeout = Finding(
        "code", "no timeout", "medium", ["bandit"], ["bandit:B113"], confidence="low", file="a.py", line=1, snippet="x"
    )
    timeout.reachability = "direct"
    assert triage.score([timeout])[0].risk == pytest.approx(4.0 * 0.6)


# ------------------------------------------------------------------------------------------------ triage
def test_fingerprints_survive_line_moves_but_not_code_changes():
    a = Finding("code", "t", "high", ["bandit"], ["bandit:B506"], file="app.py", line=82, snippet="x = yaml.load(d)")
    moved = Finding(
        "code", "t", "high", ["semgrep"], ["semgrep:x"], file="app.py", line=90, snippet="x  =  yaml.load(d)"
    )
    changed = Finding(
        "code", "t", "high", ["bandit"], ["bandit:B506"], file="app.py", line=82, snippet="y = yaml.load(d)"
    )
    assert triage.fingerprint(a) == triage.fingerprint(moved) != triage.fingerprint(changed)


def test_risk_formula_and_deadlines():
    f = Finding("dependency", "t", "high", ["pip-audit"], ["X"], package="p", version="1", advisories=["CVE-1"])
    f.reachability, f.epss, f.kev = "via requests", 0.5, True
    triage.score([f])
    assert f.risk == pytest.approx(7 * (1 + 4 * 0.5) * 2 * 0.7)
    assert f.due_days == 7  # known exploited: a week, whatever the severity


def test_suppressions_need_justification_and_expire(tmp_path):
    bad = tmp_path / "s.yaml"
    bad.write_text("- rule: bandit:B404\n  owner: me\n  expires: 2030-01-01\n")
    with pytest.raises(ValueError, match="reason"):
        triage.load_suppressions(str(bad))
    entries = triage.load_suppressions(str(DEMO / "suppressions.yaml"))
    findings = dedupe(raw_reports())
    for f in findings:
        f.fingerprint = triage.fingerprint(f)
    expired = triage.apply_suppressions(findings, entries, date(2026, 10, 20))
    assert [e["rule"] for e in expired] == ["bandit:B113"]
    assert [f.rule_ids for f in findings if f.status == "suppressed"] == [["bandit:B404"]]
    # after its expiry date, the other one stops suppressing too
    assert len(triage.apply_suppressions(findings, entries, date(2027, 5, 1))) == 2


def test_gate_fails_only_on_new_findings_at_or_above_threshold():
    findings = [
        Finding("code", "t", s, ["bandit"], ["r"], file="a.py", line=i, snippet=f"line {i}")
        for i, s in enumerate(["critical", "high", "medium"])
    ]
    for f in findings:
        f.fingerprint = triage.fingerprint(f)
    triage.apply_baseline(findings, None)
    assert [f.severity for f in triage.gate(findings)] == ["critical", "high"]
    triage.apply_baseline(findings, {findings[0].fingerprint})
    assert [f.severity for f in triage.gate(findings)] == ["high"]
    assert [f.severity for f in triage.gate(findings, "medium")] == ["high", "medium"]


def test_reachability_direct_transitive_and_unused():
    pins = {"flask": "1", "werkzeug": "1", "requests": "1", "urllib3": "1", "pyjwt": "1", "unused-lib": "1"}
    graph = {"flask": ["werkzeug", "jinja2"], "requests": ["urllib3", "idna"]}
    imported = reachability.imported_modules(DEMO / "loan-api")
    assert {"flask", "jwt", "requests", "yaml"} <= imported
    r = reachability.classify(pins, imported, lambda p, v: graph.get(p, []))
    assert r == {
        "flask": "direct",
        "requests": "direct",
        "pyjwt": "direct",
        "werkzeug": "via flask",
        "urllib3": "via requests",
        "unused-lib": "unused",
    }


def test_offline_intel_never_touches_the_network(tmp_path):
    intel = Intel(tmp_path / "empty.json", offline=True)
    with pytest.raises(OfflineMiss):
        intel.kev()


def test_full_offline_run_against_the_committed_snapshot_and_baseline(tmp_path):
    args = [
        "--root",
        str(DEMO),
        "--bandit",
        str(SCANS / "bandit.json"),
        "--sarif",
        str(SCANS / "semgrep.sarif"),
        "--pip-audit",
        str(SCANS / "pip-audit.json"),
        "--secrets",
        f"{SCANS / 'detect-secrets.json'}:loan-api",
        "--requirements",
        "loan-api/requirements.txt",
        "--src",
        "loan-api",
        "--intel",
        str(DEMO / "intel.json"),
        "--offline",
        "--report",
        str(tmp_path / "r.md"),
        "--sarif-out",
        str(tmp_path / "o.sarif"),
    ]
    assert main(args) == 1  # no baseline: every high finding is new
    assert main([*args, "--baseline", str(DEMO / "baseline.json")]) == 0
    report = (tmp_path / "r.md").read_text()
    assert "87 scanner reports merged into **50 findings**" in report and "Gate: PASS" in report


# ------------------------------------------------------------------------------------------------ remediation
class FakeIntel:
    def __init__(self, releases, affected):
        self._releases, self._affected = releases, affected

    def releases(self, pkg):
        return self._releases[pkg]

    def affected_by(self, pkg, v):
        return self._affected.get((pkg, v), set())


def test_safe_target_is_the_first_release_clear_of_every_open_advisory():
    intel = FakeIntel(
        {"p": ["1.0", "1.1", "1.2", "2.0"]},
        {("p", "1.0"): {"A", "B"}, ("p", "1.1"): {"B"}, ("p", "1.2"): {"C"}, ("p", "2.0"): set()},
    )
    assert safe_target(intel, "p", "1.0", {"A", "B"}) == "1.2"  # 1.2 has a new advisory C, but not the open ones
    assert safe_target(intel, "p", "1.0", {"A", "B", "C"}) == "2.0"
    assert safe_target(intel, "p", "2.0", {"A"}) is None


def fake_runner(breaks):
    """Tests fail if any pinned version matches a breaking rule; counts runs."""
    calls = []

    def run(pins):
        calls.append(dict(pins))
        bad = [name for name, rule in breaks.items() if rule(pins)]
        return RunResult(not bad, bad)

    return run, calls


def test_split_search_ships_everything_that_passes_and_isolates_the_breaker():
    base = {f"p{i}": "1" for i in range(8)}
    ups = [Upgrade(p, "1", "2", [f"CVE-{p}"]) for p in base]
    run, calls = fake_runner({"p5 breaks": lambda pins: pins["p5"] == "2"})
    r = verify(base, ups, run)
    assert sorted(u.package for u in r.shipped) == [p for p in base if p != "p5"]
    assert [u.package for u, _ in r.needs_code_change] == ["p5"]
    assert len(calls) == 1 + 7  # current pins, then all, halves and quarters down to p5
    assert r.pins["p5"] == "1" and r.pins["p0"] == "2"


def test_coupled_upgrades_ship_together():
    base = {"flask": "2.2", "werkzeug": "2.2", "jinja2": "3.1.2"}
    ups = [
        Upgrade("flask", "2.2", "3.1", ["CVE-f"]),
        Upgrade("jinja2", "3.1.2", "3.1.6", ["CVE-j"]),
        Upgrade("werkzeug", "2.2", "3.1", ["CVE-w"]),
    ]
    run, _ = fake_runner(
        {
            "new flask needs new werkzeug": lambda p: p["flask"] == "3.1" and p["werkzeug"] == "2.2",
            "old flask breaks on new werkzeug": lambda p: p["flask"] == "2.2" and p["werkzeug"] == "3.1",
        }
    )
    coupled = {"flask": ["werkzeug"], "werkzeug": ["flask"], "jinja2": []}
    r = verify(base, ups, run, coupled=lambda u: coupled[u.package], latest=lambda p: "9.9")
    assert sorted(u.package for u in r.shipped) == ["flask", "jinja2", "werkzeug"]
    assert r.needs_code_change == []


def test_refuses_to_start_when_tests_already_fail():
    run, _ = fake_runner({"always": lambda p: True})
    with pytest.raises(RuntimeError, match="before any upgrade"):
        verify({"a": "1"}, [Upgrade("a", "1", "2", [])], run)


def test_requirements_rewrite_keeps_comments_and_explains_changes(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# service deps\nFlask==2.2.2\nPyYAML==6.0.1\n")
    pins = read_requirements(req)
    assert pins == {"flask": "2.2.2", "pyyaml": "6.0.1"}
    out = write_requirements(req, {**pins, "flask": "3.1.3"}, [Upgrade("flask", "2.2.2", "3.1.3", ["CVE-2023-30861"])])
    assert out == "# service deps\nFlask==3.1.3  # patchpilot: 2.2.2 -> 3.1.3, fixes CVE-2023-30861\nPyYAML==6.0.1\n"
