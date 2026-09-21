"""Locate UAL export files under a file or directory target."""

from __future__ import annotations

from pathlib import Path

_SUFFIXES = (".json", ".json.gz", ".csv", ".csv.gz")


def find(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r]
    if not r.is_dir():
        return []
    out = []
    for p in sorted(r.rglob("*")):
        if p.is_file() and any(p.name.lower().endswith(s)
                               for s in _SUFFIXES):
            out.append(p)
    return out
