"""Build a synthetic systemd tree for the linux_units test-suite."""

from __future__ import annotations

import os
from pathlib import Path


def unit(root: Path, sub: str, name: str, text: str) -> Path:
    d = root / sub
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(text)
    return p


def dropin(root: Path, sub: str, unit_name: str, conf: str, text: str) -> Path:
    d = root / sub / f"{unit_name}.d"
    d.mkdir(parents=True, exist_ok=True)
    p = d / conf
    p.write_text(text)
    return p


def enable(root: Path, sub: str, target: str, unit_name: str) -> None:
    d = root / sub / target
    d.mkdir(parents=True, exist_ok=True)
    link = d / unit_name
    src = f"/usr/lib/systemd/system/{unit_name}"
    try:
        os.symlink(src, link)
    except (OSError, NotImplementedError):
        link.write_text("")          # fallback where symlinks unavailable
