"""Locate Google Drive for Desktop database files under a target root."""

from __future__ import annotations

from pathlib import Path

_NAMES = ("metadata_sqlite_db", "snapshot.db", "sync_config.db")


def find_db_files(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r] if r.name.lower() in _NAMES else []
    if not r.is_dir():
        return []
    return [p for p in r.rglob("*")
           if p.is_file() and p.name.lower() in _NAMES]
