"""Discover stores, parse each, normalise, flag, sort."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from browser_history import chromium, firefox, safari
from browser_history import flags as _flags
from browser_history.discover import find
from browser_history.model import Download, SearchTerm, Visit


@dataclass
class Result:
    entries: list = field(default_factory=list)
    stores: int = 0
    errors: list = field(default_factory=list)

    @property
    def visits(self):
        return [e for e in self.entries if isinstance(e, Visit)]

    @property
    def downloads(self):
        return [e for e in self.entries if isinstance(e, Download)]

    @property
    def searches(self):
        return [e for e in self.entries if isinstance(e, SearchTerm)]


def _parse_store(s) -> list:
    if s.family == "firefox":
        if Path(s.path).name == "downloads.sqlite":
            return firefox.parse_legacy_downloads(s.path, s.browser, s.profile)
        return firefox.parse(s.path, s.browser or "Firefox", s.profile)
    if s.family == "safari":
        return safari.parse(s.path, s.browser or "Safari", s.profile)
    return chromium.parse(s.path, s.browser or "Chrome", s.profile)


def scan(paths, *, browser: str | None = None, since: str = "",
         until: str = "", progress=None) -> Result:
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
        try:
            entries = _parse_store(s)
        except Exception as e:  # noqa: BLE001
            res.errors.append(f"{s.path}: {e}")
            continue
        for e in entries:
            kind = ("download" if isinstance(e, Download)
                    else "search" if isinstance(e, SearchTerm) else "visit")
            e.notable = _flags.flag_url(e.url, kind=kind)
            t = e.row().get("time", "")
            if since and t and t < since:
                continue
            if until and t and t > until:
                continue
            res.entries.append(e)

    res.entries.sort(key=lambda e: (e.row().get("time") or "~", e.browser))
    return res
