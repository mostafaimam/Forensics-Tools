"""Scan a LevelDB directory (.log + .ldb files) into raw Record rows."""

from __future__ import annotations

from pathlib import Path

from browser_localstorage import leveldblog, sstable
from browser_localstorage.record import Record
from browser_localstorage.sstable import SstableError
from browser_localstorage.snappy import SnappyError


def is_leveldb_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    return any(path.glob("*.log")) or any(path.glob("*.ldb")) or \
        (path / "CURRENT").exists()


def find_dirs(root: str) -> list[Path]:
    r = Path(root)
    if is_leveldb_dir(r):
        return [r]
    out = []
    for p in r.rglob("*"):
        if p.is_dir() and is_leveldb_dir(p):
            out.append(p)
    return out


def read_dir(path: Path) -> list[Record]:
    records: list[Record] = []
    for f in sorted(path.glob("*.log")):
        try:
            records.extend(leveldblog.read(str(f)))
        except OSError:
            continue
    for f in sorted(path.glob("*.ldb")):
        try:
            records.extend(sstable.read(str(f)))
        except (SstableError, SnappyError, OSError):
            continue
    return records
