"""Find .core_analytics files under a path and extract their records."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from macos_coreanalytics.parse import ParseError, load_bytes
from macos_coreanalytics.records import extract

_NAME = None  # matched by suffix below


@dataclass
class Result:
    rows: list = field(default_factory=list)
    files: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _targets(paths):
    out = []
    for p in paths:
        pp = Path(p)
        if pp.is_file():
            out.append(pp)
        elif pp.is_dir():
            out += [f for f in pp.rglob("*")
                    if f.is_file() and f.suffix == ".core_analytics"]
    return out


def collect(paths) -> Result:
    res = Result()
    for f in _targets(paths):
        try:
            data = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.files += 1
        res.sources.add(str(f))
        try:
            _kind, doc = load_bytes(data)
        except ParseError as e:
            res.errors.append(f"{f}: {e}")
            continue
        for rec in extract(doc, str(f)):
            res.rows.append(rec.row())
    res.rows.sort(key=lambda r: (r.get("timestamp") or "", r.get("app", "")))
    return res
