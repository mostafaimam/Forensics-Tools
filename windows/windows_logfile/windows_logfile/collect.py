"""Parse $LogFile inputs and reconstruct + flag events."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from windows_logfile import flags
from windows_logfile.events import reconstruct
from windows_logfile.logfile import parse

_NAME = re.compile(r"(^\$LogFile$|logfile)", re.I)


@dataclass
class Result:
    rows: list = field(default_factory=list)
    files: int = 0
    records: int = 0
    rstr_pages: int = 0
    rcrd_pages: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _targets(paths):
    out = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and (_NAME.search(f.name) or
                                    f.name == "$LogFile"):
                    out.append(f)
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
        lf = parse(data)
        res.records += len(lf.records)
        res.rstr_pages += lf.rstr_pages
        res.rcrd_pages += lf.rcrd_pages
        res.errors.extend(f"{f}: {e}" for e in lf.errors)

        events = reconstruct(lf.records, str(f))
        # detect create+delete twins by name within this file
        names_created = Counter(e.name for e in events
                                if "created" in e.action and e.name)
        names_deleted = Counter(e.name for e in events
                                if "deleted" in e.action and e.name)
        for ev in events:
            tc = ev.name and names_created.get(ev.name, 0) > 0
            td = ev.name and names_deleted.get(ev.name, 0) > 0
            n, s = flags.classify(ev, twin_create=bool(tc),
                                  twin_delete=bool(td))
            ev.notable = n
            row = ev.row()
            row["severity"] = s
            res.rows.append(row)

    res.rows.sort(key=lambda r: r.get("lsn", 0))
    return res
