"""Locate download-history stores under a filesystem root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DB_NAMES = {"History", "History.db", "places.sqlite", "downloads.sqlite"}


@dataclass
class Store:
    path: str
    family: str                      # chromium | firefox-places | firefox-legacy


def _family(name: str, path: Path) -> str:
    low = str(path).lower()
    if name == "downloads.sqlite":
        return "firefox-legacy"
    if name == "places.sqlite":
        return "firefox-places"
    if name in ("History", "History.db"):
        if "safari" in low and name == "History.db":
            return ""                # Safari has no SQLite downloads store
        if any(h in low for h in ("chrome", "chromium", "edge", "brave",
                                  "opera", "vivaldi", "yandex")):
            return "chromium"
        return "" if name == "History.db" else "chromium"
    return ""


def find(root: str) -> list[Store]:
    r = Path(root)
    out: list[Store] = []
    seen: set = set()
    if r.is_file():
        fam = _family(r.name, r) or ("chromium" if r.suffix in ("", ".db")
                                     else "")
        if fam:
            out.append(Store(str(r), fam))
        return out
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n not in _DB_NAMES:
                continue
            p = Path(dirpath) / n
            fam = _family(n, p)
            if fam and str(p) not in seen:
                seen.add(str(p))
                out.append(Store(str(p), fam))
    return out
