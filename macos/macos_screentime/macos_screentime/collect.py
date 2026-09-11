"""Find RMAdminStore-Local.sqlite (or similarly-shaped stores) and analyze."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from macos_screentime.screentime import analyze

_NAMES = ("rmadminstore-local.sqlite", "rmadminstore.sqlite")


def _targets(paths):
    out = []
    for p in paths:
        pp = Path(p)
        if pp.is_file():
            out.append(pp)
        elif pp.is_dir():
            for f in pp.rglob("*.sqlite"):
                if f.is_file() and (f.name.lower() in _NAMES or
                                    "rmadminstore" in f.name.lower()):
                    out.append(f)
    return out


@dataclass
class Result:
    rows: list = field(default_factory=list)
    stores: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def collect(paths) -> Result:
    res = Result()
    for f in _targets(paths):
        res.stores += 1
        res.sources.add(str(f))
        r = analyze(str(f))
        if r.error:
            res.errors.append(f"{f}: {r.error}")
        for u in r.rows:
            res.rows.append(u.row())
    res.rows.sort(key=lambda r: (r.get("date") or "", r.get("app", "")))
    return res
