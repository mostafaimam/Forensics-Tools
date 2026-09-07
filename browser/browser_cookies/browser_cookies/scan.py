"""Discover cookie stores, parse, flag, sort."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from browser_cookies import chromium, firefox, safari
from browser_cookies import flags as _flags
from browser_cookies.discover import find


def _profile(path: str) -> str:
    parts = Path(path).parts[:-1]
    keep = []
    for seg in reversed(parts):
        keep.append(seg)
        low = seg.lower()
        if low.endswith(".default") or "profile" in low or low in (
                "default", "network") or seg.startswith("Profile "):
            if low == "network":
                continue
            break
        if len(keep) >= 3:
            break
    return "/".join(reversed(keep)) or "?"


@dataclass
class Result:
    cookies: list = field(default_factory=list)
    stores: int = 0
    errors: list = field(default_factory=list)


def scan(paths, *, browser: str | None = None, progress=None) -> Result:
    res = Result()
    stores = []
    for raw in paths:
        stores.extend(find(str(raw)))
    if browser:
        stores = [s for s in stores
                  if browser.lower() in (s.browser or "").lower()]
    res.stores = len(stores)

    for i, s in enumerate(stores):
        if progress:
            progress(i + 1, len(stores))
        prof = _profile(s.path)
        mod = {"firefox": firefox, "safari": safari}.get(s.family, chromium)
        try:
            cookies = mod.parse(s.path, s.browser or s.family.title(), prof)
        except Exception as e:  # noqa: BLE001
            res.errors.append(f"{s.path}: {e}")
            continue
        for c in cookies:
            c.notable = _flags.flag(c)
        res.cookies.extend(cookies)

    res.cookies.sort(key=lambda c: (c.host, c.name, c.path))
    return res
