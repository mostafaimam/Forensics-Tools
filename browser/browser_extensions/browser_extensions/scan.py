"""Discover extension DBs, parse, flag, sort by risk."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from browser_extensions import chromium, firefox
from browser_extensions import flags as _flags
from browser_extensions.discover import find

_RANK = {"high": 0, "medium": 1, "low": 2}


def _profile(path: str, family: str) -> str:
    parts = Path(path).parts[:-1]
    keep = []
    for seg in reversed(parts):
        keep.append(seg)
        low = seg.lower()
        if low.endswith(".default") or "profile" in low or low == "default" \
                or seg.startswith("Profile "):
            break
        if len(keep) >= 3:
            break
    return "/".join(reversed(keep)) or "?"


@dataclass
class Result:
    extensions: list = field(default_factory=list)
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

    seen: set[tuple] = set()
    for i, s in enumerate(stores):
        if progress:
            progress(i + 1, len(stores))
        prof = _profile(s.path, s.family)
        mod = firefox if s.family == "firefox" else chromium
        try:
            exts = mod.parse(s.path, s.browser or s.family.title(), prof)
        except Exception as e:  # noqa: BLE001
            res.errors.append(f"{s.path}: {e}")
            continue
        for e in exts:
            key = (e.browser, e.profile, e.ext_id)
            if key in seen:
                continue
            seen.add(key)
            e.notable, e.risk = _flags.flag(e)
            res.extensions.append(e)

    res.extensions.sort(key=lambda e: (_RANK[e.risk], e.browser,
                                       e.name.lower()))
    return res
