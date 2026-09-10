"""Schema-tolerant reader for the PowerLog PLSQL database."""

from __future__ import annotations

import gzip
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from macos_powerlog import flags as _flags
from macos_powerlog.dbopen import connect

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# table-name regex -> (event kind, [candidate value columns])
_TABLE_MAP = [
    (re.compile(r"Application.*Agent.*_(EventForward|EventPoint|EventNone|"
                r"EventBackward)_Application$", re.I),
     ("app usage", ["BundleID", "ProcessName", "Notification"])),
    (re.compile(r"ProcessMonitorAgent.*ProcessInfo$", re.I),
     ("process", ["ProcessName", "BundleID", "PID"])),
    (re.compile(r"AccountingOperator.*Nodes$", re.I),
     ("energy", ["Node", "BundleID", "NodeType"])),
    (re.compile(r"CameraAgent.*", re.I),
     ("camera", ["Client", "BundleID", "State"])),
    (re.compile(r"(Microphone|Audio).*Agent.*", re.I),
     ("microphone", ["Client", "BundleID", "State"])),
    (re.compile(r"LocationAgent.*(Fix|ClientStatus|Client)$", re.I),
     ("location", ["Client", "BundleID", "Type"])),
    (re.compile(r"BatteryAgent.*Battery$", re.I),
     ("battery", ["Level", "RawLevel", "AdapterID"])),
    (re.compile(r"BatteryAgent.*Charge", re.I),
     ("power", ["IsCharging", "AdapterID", "Watts"])),
    (re.compile(r"(Bulletin|Notification).*Agent.*", re.I),
     ("notification", ["BundleID", "SectionID", "Title"])),
    (re.compile(r"(SpringBoard|LockState|Backlight).*Agent.*", re.I),
     ("device state", ["State", "LockState", "Backlight"])),
]


def _to_utc(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    # PowerLog uses Unix seconds; a few tables use Mac absolute time
    if f < 1_000_000_000:
        base = _MAC_EPOCH
    elif f > 3_000_000_000:                       # ms
        return _to_utc(f / 1000)
    else:
        base = datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        return (base + timedelta(seconds=f)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Event:
    timestamp: str
    kind: str
    table: str
    value: str
    detail: str
    latitude: str
    longitude: str
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {"timestamp": self.timestamp, "kind": self.kind,
                "table": self.table, "value": self.value,
                "detail": self.detail, "latitude": self.latitude,
                "longitude": self.longitude, "source": self.source,
                "notable": ";".join(self.notable)}


@dataclass
class Result:
    events: list = field(default_factory=list)
    tables: list = field(default_factory=list)
    matched_tables: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _open(path: str):
    p = Path(path)
    if p.suffix == ".gz":
        tmp = Path(tempfile.mkdtemp()) / "powerlog.PLSQL"
        with gzip.open(p, "rb") as fh, open(tmp, "wb") as out:
            shutil.copyfileobj(fh, out)
        return connect(str(tmp))
    return connect(path)


def _ts_column(cols: set[str]) -> str | None:
    for c in ("timestamp", "Timestamp", "TimeStamp", "TIMESTAMP",
              "timestampLogged", "timestampEnd", "startTime"):
        if c in cols:
            return c
    return None


def list_tables(path: str) -> list[str]:
    with _open(path) as con:
        return [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "ORDER BY name")]


def dump_table(path: str, table: str, limit: int = 0) -> list[dict]:
    with _open(path) as con:
        con.row_factory = sqlite3.Row
        q = f'SELECT * FROM "{table}"'
        if limit:
            q += f" LIMIT {int(limit)}"
        try:
            return [dict(r) for r in con.execute(q)]
        except sqlite3.Error as e:
            raise ValueError(str(e)) from None


def collect(path: str) -> Result:
    res = Result()
    with _open(path) as con:
        con.row_factory = sqlite3.Row
        res.tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]

        for name in res.tables:
            kind_cols = None
            for rx, kc in _TABLE_MAP:
                if rx.search(name):
                    kind_cols = kc
                    break
            if kind_cols is None:
                continue
            kind, value_cols = kind_cols
            try:
                cols = {r[1] for r in con.execute(
                    f'PRAGMA table_info("{name}")')}
            except sqlite3.Error:
                continue
            tsc = _ts_column(cols)
            if tsc is None:
                continue
            vcol = next((c for c in value_cols if c in cols), None)
            lat = "Latitude" if "Latitude" in cols else (
                "latitude" if "latitude" in cols else None)
            lon = "Longitude" if "Longitude" in cols else (
                "longitude" if "longitude" in cols else None)
            state_col = next((c for c in ("State", "state", "Notification",
                                          "LockState", "IsCharging")
                              if c in cols), None)

            sel = [f'"{tsc}" AS ts']
            sel.append(f'"{vcol}" AS val' if vcol else "NULL AS val")
            sel.append(f'"{state_col}" AS st' if state_col else "NULL AS st")
            sel.append(f'"{lat}" AS lat' if lat else "NULL AS lat")
            sel.append(f'"{lon}" AS lon' if lon else "NULL AS lon")
            try:
                rows = con.execute(
                    f'SELECT {", ".join(sel)} FROM "{name}"').fetchall()
            except sqlite3.Error as e:
                res.errors.append(f"{name}: {e}")
                continue
            res.matched_tables.append(name)
            for r in rows:
                ev = Event(
                    timestamp=_to_utc(r["ts"]), kind=kind, table=name,
                    value=str(r["val"] or ""),
                    detail=str(r["st"] or ""),
                    latitude=("" if r["lat"] in (None, "") else
                              f'{float(r["lat"]):.5f}'),
                    longitude=("" if r["lon"] in (None, "") else
                               f'{float(r["lon"]):.5f}'),
                    source=path)
                ev.notable = _flags.flag(ev)
                res.events.append(ev)

    res.events.sort(key=lambda e: (e.timestamp or "", e.kind))
    return res
