"""Lay a synthetic UsrClass.dat into a mounted-image-shaped tree."""

from __future__ import annotations

from pathlib import Path

from _hive_synth import build_usrclass


def build_root(root: Path, user: str = "testuser") -> Path:
    d = root / "Users" / user / "AppData/Local/Microsoft/Windows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "UsrClass.dat").write_bytes(build_usrclass())
    return root


def write_hive(path: Path) -> Path:
    path.write_bytes(build_usrclass())
    return path
