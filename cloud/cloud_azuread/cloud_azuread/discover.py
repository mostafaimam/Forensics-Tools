"""Locate Entra ID log export files under a file or directory target."""

from __future__ import annotations

from pathlib import Path


def find(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r]
    if not r.is_dir():
        return []
    out = []
    for p in sorted(r.rglob("*")):
        if p.is_file() and (p.name.endswith(".json") or
                            p.name.endswith(".json.gz")):
            out.append(p)
    return out
