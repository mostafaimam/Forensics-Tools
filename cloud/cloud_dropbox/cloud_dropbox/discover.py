"""Locate Dropbox client database files under a target root."""

from __future__ import annotations

from pathlib import Path

_NAMES = ("config.dbx", "filecache.dbx", "deleted.dbx",
         "config.db", "filecache.db")


def find_db_files(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r] if r.name.lower() in _NAMES else []
    if not r.is_dir():
        return []
    return [p for p in r.rglob("*")
           if p.is_file() and p.name.lower() in _NAMES]
