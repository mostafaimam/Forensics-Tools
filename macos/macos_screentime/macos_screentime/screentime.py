"""Extract daily app / category usage totals from RMAdminStore-Local.sqlite."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from macos_screentime import coredata
from macos_screentime.dbopen import connect

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _mac_time(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if not f:
        return ""
    try:
        return (_MAC_EPOCH + timedelta(seconds=f)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class UsageRow:
    entity: str
    app: str
    duration_s: float
    start: str
    end: str
    date: str
    device: str
    source: str

    def row(self) -> dict:
        return {
            "date": self.date or self.start[:10], "entity": self.entity,
            "app": self.app, "duration_s": self.duration_s,
            "start": self.start, "end": self.end, "device": self.device,
            "source": self.source,
        }


@dataclass
class Result:
    rows: list = field(default_factory=list)
    entities_seen: list = field(default_factory=list)
    usage_entities: list = field(default_factory=list)
    error: str = ""


def analyze(path: str) -> Result:
    res = Result()
    try:
        with connect(path) as con:
            con.row_factory = sqlite3.Row
            ents = coredata.entities(con)
            res.entities_seen = [(e.name, e.table) for e in ents]
            guesses = coredata.guess_usage_entities(ents)
            res.usage_entities = [g.entity.name for g in guesses]
            for g in guesses:
                e = g.entity
                try:
                    cur = con.execute(f'SELECT * FROM "{e.table}"')
                except sqlite3.Error:
                    continue
                for row in cur:
                    d = dict(row)
                    app = str(d.get(g.app_col, "")) if g.app_col else ""
                    dur = d.get(g.duration_col) if g.duration_col else None
                    start = _mac_time(d.get(g.start_col)) \
                        if g.start_col else ""
                    end = _mac_time(d.get(g.end_col)) if g.end_col else ""
                    date = _mac_time(d.get(g.date_col)) if g.date_col else ""
                    device = str(d.get(g.device_col, "")) \
                        if g.device_col else ""
                    if not (app or dur or start):
                        continue
                    try:
                        dur_f = float(dur) if dur is not None else 0.0
                    except (TypeError, ValueError):
                        dur_f = 0.0
                    res.rows.append(UsageRow(
                        entity=e.name, app=app, duration_s=dur_f,
                        start=start, end=end, date=date, device=device,
                        source=path))
    except sqlite3.Error as e:
        res.error = str(e)
    res.rows.sort(key=lambda r: (r.date or r.start or "", r.app))
    return res


def dump_entity(path: str, name: str) -> list[dict]:
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        ents = {e.name.lower(): e for e in coredata.entities(con)}
        e = ents.get(name.lower())
        if not e:
            return []
        return [dict(r) for r in con.execute(f'SELECT * FROM "{e.table}"')]
