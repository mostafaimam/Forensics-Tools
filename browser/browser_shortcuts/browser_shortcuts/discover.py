"""Locate Chromium Shortcuts / Top Sites / Network Action Predictor stores."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from browser_shortcuts.dbopen import connect, has_table

_NAMES = {
    "Shortcuts": "shortcuts",
    "Top Sites": "top_sites",
    "Network Action Predictor": "predictor",
}

_TABLE_BY_KIND = {
    "shortcuts": "omni_box_shortcuts",
    "top_sites": "top_sites",
    "predictor": "network_action_predictor",
}

_BROWSER_HINTS = [
    ("edge", "Edge"), ("brave", "Brave"), ("vivaldi", "Vivaldi"),
    ("opera", "Opera"), ("chromium", "Chromium"), ("chrome", "Chrome"),
]


@dataclass
class Store:
    path: str
    kind: str          # shortcuts | top_sites | predictor
    browser: str
    profile: str


def _browser_from_path(path: Path) -> str:
    low = str(path).lower().replace("\\", "/")
    for needle, name in _BROWSER_HINTS:
        if needle in low:
            return name
    return "?"


def _profile(path: Path) -> str:
    return path.parent.name or "?"


def _verify(path: Path, kind: str) -> bool:
    try:
        with connect(path) as con:
            return has_table(con, _TABLE_BY_KIND[kind])
    except sqlite3.Error:
        return False


def find(root: str) -> list[Store]:
    r = Path(root)
    stores: list[Store] = []
    if r.is_file():
        kind = _NAMES.get(r.name)
        if kind and _verify(r, kind):
            stores.append(Store(str(r), kind, _browser_from_path(r),
                                _profile(r)))
        return stores
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            kind = _NAMES.get(n)
            if not kind:
                continue
            p = Path(dirpath) / n
            if _verify(p, kind):
                stores.append(Store(str(p), kind, _browser_from_path(p),
                                    _profile(p)))
    return stores
