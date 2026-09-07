"""Locate browser history stores under a filesystem root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DB_NAMES = {"History", "History.db", "places.sqlite", "downloads.sqlite"}

_BROWSER_HINTS = [
    ("edge", "Edge"), ("brave", "Brave"), ("vivaldi", "Vivaldi"),
    ("opera", "Opera"), ("chromium", "Chromium"), ("chrome", "Chrome"),
    ("tor browser", "Tor Browser"), ("torbrowser", "Tor Browser"),
    ("firefox", "Firefox"), ("mozilla", "Firefox"),
    ("safari", "Safari"), ("yandex", "Yandex"),
]

# family: how to parse it
_CHROMIUM = {"Chrome", "Edge", "Brave", "Vivaldi", "Opera", "Chromium",
             "Yandex"}
_FIREFOX = {"Firefox", "Tor Browser"}


@dataclass
class Store:
    path: str
    browser: str
    family: str                # chromium | firefox | safari
    profile: str


def _browser_from_path(path: Path) -> str:
    low = str(path).lower().replace("\\", "/")
    for needle, name in _BROWSER_HINTS:
        if needle in low:
            return name
    return ""


def _family(browser: str, name: str) -> str:
    if name == "places.sqlite" or name == "downloads.sqlite":
        return "firefox"
    if name == "History.db" and browser in ("Safari", ""):
        return "safari"
    if browser in _FIREFOX:
        return "firefox"
    if browser in _CHROMIUM:
        return "chromium"
    # History.db could still be Safari; bare History is chromium
    return "safari" if name == "History.db" else "chromium"


def _profile(path: Path) -> str:
    parts = path.parts
    keep = []
    for seg in parts[:-1][::-1]:
        s = seg.strip()
        if s.lower() in ("history", "default", "user data"):
            keep.append(s)
        elif any(h in s.lower() for h, _ in _BROWSER_HINTS) or \
                s.lower().endswith(".default") or "profile" in s.lower() \
                or s.startswith("Profile "):
            keep.append(s)
            break
        else:
            keep.append(s)
            if len(keep) >= 3:
                break
    return "/".join(keep[::-1]) or (path.parent.name or "?")


def find(root: str) -> list[Store]:
    r = Path(root)
    stores: list[Store] = []
    if r.is_file():
        if r.name in _DB_NAMES or r.suffix in ("", ".db", ".sqlite"):
            b = _browser_from_path(r)
            stores.append(Store(str(r), b or "?",
                                _family(b, r.name), r.parent.name or "?"))
        return stores
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n not in _DB_NAMES:
                continue
            p = Path(dirpath) / n
            b = _browser_from_path(p)
            stores.append(Store(str(p), b or "?", _family(b, n), _profile(p)))
    # dedupe on path
    seen = set()
    uniq = []
    for s in stores:
        if s.path not in seen:
            seen.add(s.path)
            uniq.append(s)
    return uniq
