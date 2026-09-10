"""Discover package logs under a root, parse and flag."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from linux_packages import flags as _flags
from linux_packages import parse as _parse

_LOG_GLOBS = [
    "var/log/dpkg.log", "var/log/dpkg.log.*",
    "var/log/apt/history.log", "var/log/apt/history.log.*",
    "var/log/dnf.log", "var/log/dnf.log.*", "var/log/dnf.rpm.log",
    "var/log/dnf.rpm.log.*", "var/log/yum.log", "var/log/yum.log.*",
    "var/lib/dnf/history.sqlite", "var/lib/dnf/history/history.sqlite",
]


@dataclass
class Result:
    events: list = field(default_factory=list)
    files: int = 0
    files_seen: list = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _discover(root: str) -> list[str]:
    r = Path(root)
    if r.is_file():
        return [str(r)]
    out: list[str] = []
    for g in _LOG_GLOBS:
        for m in r.glob(g):
            if m.is_file():
                out.append(str(m))
    # dnf history dir may hold history.sqlite plus rotated copies
    hd = r / "var/lib/dnf/history"
    if hd.is_dir():
        out += [str(p) for p in hd.glob("*.sqlite")]
    return sorted(set(out))


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    seen: set = set()
    for path in paths:
        files = _discover(str(path))
        for f in files:
            res.files += 1
            res.files_seen.append(f)
            try:
                for ev in _parse.read(f):
                    key = (ev.ts, ev.action, ev.package, ev.version,
                           ev.source)
                    if key in seen:
                        continue
                    seen.add(key)
                    ev.notable = _flags.flag(ev)
                    res.sources[ev.source] = res.sources.get(ev.source, 0) + 1
                    res.events.append(ev)
                    if progress and len(res.events) % 5000 == 0:
                        progress(len(res.events))
            except (OSError, ValueError) as e:
                res.errors.append(f"{f}: {e}")

    res.findings = _flags.aggregate(res.events)   # may append to ev.notable
    for ev in res.events:
        s: set = set()
        ev.notable = [n for n in ev.notable if not (n in s or s.add(n))]
    res.events.sort(key=lambda e: (not e.ts, e.ts, e.package))
    return res
