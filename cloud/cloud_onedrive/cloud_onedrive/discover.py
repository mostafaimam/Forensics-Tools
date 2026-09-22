"""Locate OneDrive's settings directory contents under a target root.

Looks for anything under a path containing both ``OneDrive`` and
``settings`` (case-insensitive) - this is deliberately permissive
about exact directory depth/name, since the vendored layout has shifted
across client versions and account types (Personal / Business1 / ...).
"""

from __future__ import annotations

from pathlib import Path


def _under_onedrive_settings(p: Path) -> bool:
    parts = [seg.lower() for seg in p.parts]
    return "onedrive" in parts and "settings" in parts


def find_db_files(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r] if "syncenginedatabase" in r.name.lower() else []
    if not r.is_dir():
        return []
    return [p for p in r.rglob("*")
           if p.is_file() and "syncenginedatabase" in p.name.lower()]


def find_settings_files(root: str) -> list[Path]:
    r = Path(root)
    if r.is_file():
        return [r] if r.suffix.lower() in (".ini", ".dat") else []
    if not r.is_dir():
        return []
    return [p for p in r.rglob("*")
           if p.is_file() and _under_onedrive_settings(p)
           and p.suffix.lower() in (".ini", ".dat")
           and "syncenginedatabase" not in p.name.lower()]
