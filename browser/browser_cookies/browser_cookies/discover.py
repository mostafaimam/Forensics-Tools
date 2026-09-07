"""Locate browser cookie stores under a filesystem root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DB_NAMES = {"Cookies", "cookies.sqlite", "Cookies.binarycookies",
             "Safe Browsing Cookies"}

_BROWSER_HINTS = [
    ("edge", "Edge"), ("brave", "Brave"), ("vivaldi", "Vivaldi"),
    ("opera", "Opera"), ("chromium", "Chromium"), ("chrome", "Chrome"),
    ("tor browser", "Tor Browser"), ("torbrowser", "Tor Browser"),
    ("firefox", "Firefox"), ("mozilla", "Firefox"),
    ("safari", "Safari"), ("yandex", "Yandex"),
]
_CHROMIUM = {"Chrome", "Edge", "Brave", "Vivaldi", "Opera", "Chromium",
             "Yandex"}
_FIREFOX = {"Firefox", "Tor Browser"}


@dataclass
class Store:
    path: str
    browser: str
    family: str                # chromium | firefox | safari


def _browser_from_path(path: Path) -> str:
    low = str(path).lower().replace("\\", "/")
    for needle, name in _BROWSER_HINTS:
        if needle in low:
            return name
    return ""


def _family(browser: str, name: str) -> str:
    if name == "cookies.sqlite":
        return "firefox"
    if name == "Cookies.binarycookies":
        return "safari"
    if browser in _FIREFOX:
        return "firefox"
    if browser in _CHROMIUM:
        return "chromium"
    return "chromium"


def find(root: str) -> list[Store]:
    r = Path(root)
    out: list[Store] = []
    if r.is_file():
        b = _browser_from_path(r)
        out.append(Store(str(r), b or "?", _family(b, r.name)))
        return out
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n not in _DB_NAMES:
                continue
            p = Path(dirpath) / n
            b = _browser_from_path(p)
            fam = _family(b, n)
            if not b and fam == "safari":
                b = "Safari"          # only Safari uses Cookies.binarycookies
            out.append(Store(str(p), b or "?", fam))
    seen = set()
    uniq = []
    for s in out:
        if s.path not in seen:
            seen.add(s.path)
            uniq.append(s)
    return uniq
