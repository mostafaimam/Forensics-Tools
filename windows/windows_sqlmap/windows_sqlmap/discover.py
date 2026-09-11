"""Find SQLite databases anywhere under a path, by header magic."""

from __future__ import annotations

from pathlib import Path

_MAGIC = b"SQLite format 3\x00"


def is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(16) == _MAGIC
    except OSError:
        return False


def find(paths) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_file():
            if is_sqlite(pp):
                out.append(pp)
            continue
        if not pp.is_dir():
            continue
        for f in pp.rglob("*"):
            if f.is_file() and f.stat().st_size >= 100 and is_sqlite(f):
                out.append(f)
    return out
