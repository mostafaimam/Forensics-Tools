"""Discover bookmark stores and parse them."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from browser_bookmarks import parse as _parse

_NAMES = {"Bookmarks", "places.sqlite"}


@dataclass
class Result:
    bookmarks: list = field(default_factory=list)
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


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        try:
            stores = _find(str(path))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        for st in stores:
            res.stores += 1
            try:
                if Path(st).name == "places.sqlite":
                    res.bookmarks += _parse.parse_firefox(st)
                else:
                    res.bookmarks += _parse.parse_chromium(st)
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{st}: {e}")
    res.bookmarks.sort(key=lambda b: (not b.date_added, b.date_added or "",
                                      b.folder, b.title))
    return res
