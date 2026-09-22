"""Locate candidate Box Drive database files under a target root.

Box's exact database filename isn't confidently known here (unlike
this suite's other cloud-sync tools) - candidates are any file with a
database-shaped extension under a path that mentions Box, verified by
magic bytes rather than trusted by name.
"""

from __future__ import annotations

from pathlib import Path

_EXTENSIONS = (".db", ".sqlite", ".sqlite3", ".dat")


def _under_box(p: Path) -> bool:
    return any("box" in seg.lower() for seg in p.parts)


def find_candidates(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r] if r.suffix.lower() in _EXTENSIONS else []
    if not r.is_dir():
        return []
    return [p for p in r.rglob("*")
           if p.is_file() and p.suffix.lower() in _EXTENSIONS
           and _under_box(p)]
