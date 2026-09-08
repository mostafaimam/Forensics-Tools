"""Discover Web Data / formhistory stores and parse them."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from browser_autofill import parse as _parse

_NAMES = {"Web Data", "web data", "formhistory.sqlite"}


@dataclass
class Result:
    records: list = field(default_factory=list)
    stores: int = 0
    errors: list = field(default_factory=list)


def _find(root: str) -> list[str]:
    r = Path(root)
    if r.is_file():
        return [str(r)]
    out: list[str] = []
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n in _NAMES:
                out.append(str(Path(dirpath) / n))
    return out


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    for path in paths:
        try:
            stores = _find(str(path))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        if not stores and Path(path).is_file():
            stores = [str(path)]
        for st in stores:
            res.stores += 1
            name = Path(st).name.lower()
            try:
                if name == "formhistory.sqlite":
                    res.records += _parse.parse_formhistory(st)
                else:
                    res.records += _parse.parse_web_data(st)
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{st}: {e}")
    res.records.sort(key=lambda r: (not r.last_used, r.last_used or "",
                                    r.name))
    return res
