"""How many test-suite runs does it take to find the largest set of upgrades that passes?

Compares, by simulation, three strategies on n pending upgrades of which k break the tests independently:
  all at once:   one run; if anything breaks, nothing ships
  one at a time: n runs, then one run of everything that passed together (interactions can still break)
  split search:  patchpilot's recursive halving; ships every passing half on top of what already passed
The real demo is reported alongside from demo/triage.json.

    uv run python bench/strategies.py
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from patchpilot.remediate import RunResult, Upgrade, verify

ROOT = Path(__file__).resolve().parent.parent


def split_search_runs(n: int, broken: set[int]) -> int:
    base = {f"p{i}": "1" for i in range(n)}
    ups = [Upgrade(f"p{i}", "1", "2", []) for i in range(n)]
    r = verify(base, ups, lambda pins: RunResult(not any(pins[f"p{i}"] == "2" for i in broken)))
    assert len(r.shipped) == n - len(broken)
    return len(r.runs) - 1  # not counting the run on current pins, which every strategy needs


def main() -> None:
    rng = random.Random(0)
    rows = []
    for n in (6, 20, 50):
        for k in (0, 1, 2, 3, 5):
            if k > n:
                continue
            trials = [split_search_runs(n, set(rng.sample(range(n), k))) for _ in range(400)]
            rows.append(
                {
                    "upgrades": n,
                    "breaking": k,
                    "one_at_a_time": n + 1,
                    "split_search_mean": round(sum(trials) / len(trials), 1),
                    "split_search_max": max(trials),
                    "all_at_once_ships": "all" if k == 0 else "nothing",
                }
            )
    demo = json.loads((ROOT / "demo" / "triage.json").read_text())["remediation"]
    out = {
        "simulation": rows,
        "demo": {
            "test_runs": len(demo["runs"]),
            "shipped": len(demo["shipped"]),
            "needs_code_change": len(demo["needs_code_change"]),
        },
    }
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "strategies.json").write_text(json.dumps(out, indent=1) + "\n")
    print(f"{'n':>3} {'k':>2} {'one at a time':>14} {'split (mean)':>13} {'split (max)':>12}")
    for r in rows:
        print(
            f"{r['upgrades']:>3} {r['breaking']:>2} {r['one_at_a_time']:>14} {r['split_search_mean']:>13} "
            f"{r['split_search_max']:>12}"
        )
    print("demo:", out["demo"])


if __name__ == "__main__":
    main()
