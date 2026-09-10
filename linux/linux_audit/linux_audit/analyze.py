"""Discover audit logs under a root, parse and flag."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from linux_audit import flags as _flags
from linux_audit import parse as _parse

_GLOBS = ["var/log/audit/audit.log", "var/log/audit/audit.log.*",
          "var/log/audit/audit.log*.gz"]


@dataclass
class Result:
    events: list = field(default_factory=list)
    files: list = field(default_factory=list)
    records: int = 0
    unparsed: int = 0
    actions: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def discover(path: str) -> list[str]:
    p = Path(path)
    if p.is_file():
        return [str(p)]
    out: list[str] = []
    for g in _GLOBS:
        out += [str(m) for m in p.glob(g) if m.is_file()]
    return sorted(set(out))


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    for path in paths:
        for f in discover(str(path)):
            res.files.append(f)
            recs: list = []
            try:
                for ln in _parse._read_lines(Path(f)):
                    r = _parse.parse_line(ln)
                    if r is None:
                        res.unparsed += 1
                    else:
                        recs.append(r)
                        res.records += 1
            except (OSError, ValueError) as e:
                res.errors.append(f"{f}: {e}")
                continue
            for ev in _parse.assemble(recs, Path(f).name):
                ev.notable = _flags.flag(ev)
                res.actions[ev.action] = res.actions.get(ev.action, 0) + 1
                res.events.append(ev)
                if progress and len(res.events) % 10000 == 0:
                    progress(len(res.events))

    res.events.sort(key=lambda e: (not e.ts, e.epoch, e.serial))
    return res
