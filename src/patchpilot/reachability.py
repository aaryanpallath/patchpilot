"""Is a vulnerable package actually used? Imports are read from the service's source with the ast module, and
packages pulled in by an imported package count as transitively reachable."""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

# distributions whose import name differs from the package name
IMPORT_NAMES = {
    "pyjwt": "jwt",
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "opencv-python": "cv2",
    "protobuf": "google",
}


def imported_modules(src_dir: str | Path, exclude: tuple[str, ...] = ("tests",)) -> set[str]:
    mods: set[str] = set()
    for path in Path(src_dir).rglob("*.py"):
        if any(part in exclude for part in path.parts):
            continue
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods.add(node.module.split(".")[0])
    return mods


def import_name(package: str) -> str:
    return IMPORT_NAMES.get(package.lower(), package.lower().replace("-", "_"))


def classify(pins: dict[str, str], imported: set[str], requires: Callable[[str, str], list[str]]) -> dict[str, str]:
    """For each pinned package: 'direct' (imported), 'via <pkg>' (a dependency of an imported package), or
    'unused' (pinned but never imported; still installed, so still a risk, but a lower one)."""
    out: dict[str, str] = {}
    direct = [p for p in pins if import_name(p) in imported]
    for p in direct:
        out[p] = "direct"
    frontier = list(direct)
    while frontier:  # breadth-first through the pinned dependency graph
        parent = frontier.pop(0)
        for child in requires(parent, pins[parent]):
            if child in pins and child not in out:
                out[child] = f"via {parent}"
                frontier.append(child)
    for p in pins:
        out.setdefault(p, "unused")
    return out
