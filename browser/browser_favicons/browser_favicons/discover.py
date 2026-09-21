"""Locate Chromium Favicons / Firefox favicons.sqlite stores."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from browser_favicons.dbopen import connect, has_table

_NAMES = {"Favicons": "chromium", "favicons.sqlite": "firefox"}


@dataclass
class Store:
    path: str
    family: str    # chromium | firefox
    profile: str


def _verify(path: Path, family: str) -> bool:
    try:
        with connect(path) as con:
            if family == "chromium":
                return has_table(con, "favicons") and \
                    has_table(con, "icon_mapping")
            return has_table(con, "moz_icons")
    except sqlite3.Error:
        return False


def find(root: str) -> list[Store]:
    r = Path(root)
    stores: list[Store] = []
    if r.is_file():
        family = _NAMES.get(r.name)
        if family and _verify(r, family):
            stores.append(Store(str(r), family, r.parent.name or "?"))
        return stores
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            family = _NAMES.get(n)
            if not family:
                continue
            p = Path(dirpath) / n
            if _verify(p, family):
                stores.append(Store(str(p), family, p.parent.name or "?"))
    return stores
