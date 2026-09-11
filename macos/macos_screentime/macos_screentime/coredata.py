"""Generic Core Data SQLite introspection (the Z_PRIMARYKEY convention)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

_USAGE_NAME_HINTS = ("usage", "activity", "duration", "session")
_APP_COL_HINTS = ("bundleidentifier", "bundleid", "identifier", "appname",
                  "displayname", "name")
_DUR_COL_HINTS = ("totaltime", "duration", "totalduration", "usagetime")
_START_COL_HINTS = ("starttime", "startdate", "begin")
_END_COL_HINTS = ("endtime", "enddate", "end")
_DATE_COL_HINTS = ("date", "day")


@dataclass
class Entity:
    ent_id: int
    name: str
    table: str
    columns: list


@dataclass
class UsageGuess:
    entity: Entity
    app_col: str = ""
    duration_col: str = ""
    start_col: str = ""
    end_col: str = ""
    date_col: str = ""
    device_col: str = ""


def entities(con: sqlite3.Connection) -> list[Entity]:
    out = []
    try:
        rows = con.execute(
            "SELECT Z_ENT, Z_NAME FROM Z_PRIMARYKEY").fetchall()
    except sqlite3.Error:
        rows = []
    tables = {r[0].upper() for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for ent_id, name in rows:
        table = f"Z{name.upper()}"
        if table not in tables:
            # some stores pluralise or namespace the table differently
            cand = [t for t in tables if t.endswith(name.upper())]
            if not cand:
                continue
            table = cand[0]
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
        out.append(Entity(ent_id=ent_id, name=name, table=table,
                          columns=cols))
    return out


def _find_col(cols, hints) -> str:
    low = {c.lower().lstrip("z"): c for c in cols}
    for h in hints:
        for k, orig in low.items():
            if h in k:
                return orig
    return ""


def guess_usage_entities(ents: list[Entity]) -> list[UsageGuess]:
    out = []
    for e in ents:
        name_l = e.name.lower()
        cols_l = " ".join(c.lower() for c in e.columns)
        looks_usage = any(h in name_l for h in _USAGE_NAME_HINTS) or \
            any(h in cols_l for h in _DUR_COL_HINTS)
        if not looks_usage:
            continue
        g = UsageGuess(entity=e)
        g.app_col = _find_col(e.columns, _APP_COL_HINTS)
        g.duration_col = _find_col(e.columns, _DUR_COL_HINTS)
        g.start_col = _find_col(e.columns, _START_COL_HINTS)
        g.end_col = _find_col(e.columns, _END_COL_HINTS)
        g.date_col = _find_col(e.columns, _DATE_COL_HINTS)
        g.device_col = _find_col(e.columns, ("device",))
        if g.app_col or g.duration_col or g.start_col:
            out.append(g)
    return out
