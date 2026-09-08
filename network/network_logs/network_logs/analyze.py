"""Read every log, normalise, flag, and sort into one event stream."""

from __future__ import annotations

from dataclasses import dataclass, field

from network_logs import flags as _flags
from network_logs import formats as _formats


@dataclass
class Result:
    events: list = field(default_factory=list)
    formats: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    evs: list = []
    for path in paths:
        try:
            for ev in _formats.read(path):
                evs.append(ev)
                res.formats[ev.fmt] = res.formats.get(ev.fmt, 0) + 1
                if progress and len(evs) % 10000 == 0:
                    progress(len(evs))
        except (_formats.LogError, OSError) as e:
            res.errors.append(str(e))

    for ev in evs:
        ev.notable = _flags.flag(ev)
    res.findings = _flags.aggregate(evs)

    res.events = sorted(evs, key=lambda e: (e.ts is None, e.ts or 0.0))
    return res
