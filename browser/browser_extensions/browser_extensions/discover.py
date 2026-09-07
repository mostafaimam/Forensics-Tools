"""Locate extension databases under a filesystem root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_NAMES = {"Preferences", "Secure Preferences", "extensions.json"}

_HINTS = [
    ("edge", "Edge"), ("brave", "Brave"), ("vivaldi", "Vivaldi"),
    ("opera", "Opera"), ("chromium", "Chromium"), ("chrome", "Chrome"),
    ("tor browser", "Tor Browser"), ("torbrowser", "Tor Browser"),
    ("firefox", "Firefox"), ("mozilla", "Firefox"),
]
_CHROMIUM = {"Chrome", "Edge", "Brave", "Vivaldi", "Opera", "Chromium"}


@dataclass
class Store:
    path: str
    browser: str
    family: str                # chromium | firefox


def _browser(path: Path) -> str:
    low = str(path).lower().replace("\\", "/")
    for needle, name in _HINTS:
        if needle in low:
            return name
    return ""


def find(root: str) -> list[Store]:
    r = Path(root)
    out: list[Store] = []
    if r.is_file():
        b = _browser(r)
        fam = "firefox" if r.name == "extensions.json" else "chromium"
        out.append(Store(str(r), b or ("Firefox" if fam == "firefox"
                                       else "?"), fam))
        return out
    prof_pref: dict[str, str] = {}
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n not in _NAMES:
                continue
            p = Path(dirpath) / n
            b = _browser(p)
            if n == "extensions.json":
                out.append(Store(str(p), b or "Firefox", "firefox"))
            else:
                # prefer 'Preferences'; fall back to 'Secure Preferences'
                key = dirpath
                if n == "Preferences" or key not in prof_pref:
                    prof_pref[key] = str(p)
    for path in prof_pref.values():
        b = _browser(Path(path))
        if b in _CHROMIUM or (not b):
            out.append(Store(path, b or "Chrome", "chromium"))
    seen = set()
    uniq = []
    for s in out:
        if s.path not in seen:
            seen.add(s.path)
            uniq.append(s)
    return uniq
