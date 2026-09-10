"""Read ZLIVEUSAGE / ZPROCESS / ZNETWORKATTACHMENT from netusage.sqlite."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from macos_netusage import flags as _flags
from macos_netusage.dbopen import connect

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _utc(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    if f > 3_000_000_000:
        f -= _MAC_EPOCH.timestamp()
    try:
        return (_MAC_EPOCH + timedelta(seconds=f)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class ProcUsage:
    process: str
    bundle: str
    first_seen: str
    last_seen: str
    wifi_in: int
    wifi_out: int
    wwan_in: int
    wwan_out: int
    wired_in: int
    wired_out: int
    rows: int
    source: str = ""
    notable: list = field(default_factory=list)

    @property
    def total_in(self) -> int:
        return self.wifi_in + self.wwan_in + self.wired_in

    @property
    def total_out(self) -> int:
        return self.wifi_out + self.wwan_out + self.wired_out

    def row(self) -> dict:
        return {
            "process": self.process, "bundle": self.bundle,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "total_in": self.total_in, "total_out": self.total_out,
            "wifi_in": self.wifi_in, "wifi_out": self.wifi_out,
            "wwan_in": self.wwan_in, "wwan_out": self.wwan_out,
            "wired_in": self.wired_in, "wired_out": self.wired_out,
            "rows": self.rows, "source": self.source,
            "notable": ";".join(self.notable),
        }


@dataclass
class Attachment:
    identifier: str
    kind: str
    first_seen: str
    last_seen: str

    def row(self) -> dict:
        return {"identifier": self.identifier, "kind": self.kind,
                "first_seen": self.first_seen, "last_seen": self.last_seen}


@dataclass
class Result:
    processes: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _col(cols: set[str], *names: str):
    for n in names:
        if n in cols:
            return n
    return None


def parse(path: str) -> Result:
    res = Result()
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "ZLIVEUSAGE" not in tables:
            res.errors.append("ZLIVEUSAGE table not found")
            return res

        pcols = {r[1] for r in con.execute("PRAGMA table_info(ZPROCESS)")} \
            if "ZPROCESS" in tables else set()
        pname = _col(pcols, "ZPROCNAME", "ZPROCESSNAME", "ZNAME")
        pbundle = _col(pcols, "ZBUNDLENAME", "ZBUNDLEID")
        procs: dict[int, tuple[str, str]] = {}
        if pname:
            for r in con.execute(
                    f'SELECT Z_PK, "{pname}" AS n'
                    + (f', "{pbundle}" AS b' if pbundle else ', NULL AS b')
                    + ' FROM ZPROCESS'):
                procs[r["Z_PK"]] = (str(r["n"] or ""), str(r["b"] or ""))

        lcols = {r[1] for r in con.execute("PRAGMA table_info(ZLIVEUSAGE)")}
        link = _col(lcols, "ZHASPROCESS", "ZPROCESS")
        ts = _col(lcols, "ZTIMESTAMP", "ZTIMESTAMP1")
        m = {
            "wifi_in": _col(lcols, "ZWIFIIN"),
            "wifi_out": _col(lcols, "ZWIFIOUT"),
            "wwan_in": _col(lcols, "ZWWANIN"),
            "wwan_out": _col(lcols, "ZWWANOUT"),
            "wired_in": _col(lcols, "ZWIREDIN", "ZBYTESIN"),
            "wired_out": _col(lcols, "ZWIREDOUT", "ZBYTESOUT"),
        }
        sel = [f'"{link}" AS lk' if link else "NULL AS lk",
               f'"{ts}" AS ts' if ts else "NULL AS ts"]
        for k, c in m.items():
            sel.append(f'"{c}" AS {k}' if c else f"0 AS {k}")
        agg: dict[int, dict] = {}
        for r in con.execute(f'SELECT {", ".join(sel)} FROM ZLIVEUSAGE'):
            pk = r["lk"]
            a = agg.setdefault(pk, {k: 0 for k in m} | {"rows": 0,
                                                        "first": "", "last": ""})
            for k in m:
                try:
                    a[k] += int(r[k] or 0)
                except (TypeError, ValueError):
                    pass
            a["rows"] += 1
            tt = _utc(r["ts"])
            if tt:
                a["first"] = min(a["first"], tt) if a["first"] else tt
                a["last"] = max(a["last"], tt)

        for pk, a in agg.items():
            name, bundle = procs.get(pk, (f"#{pk}", ""))
            pu = ProcUsage(
                process=name or bundle or f"#{pk}", bundle=bundle,
                first_seen=a["first"], last_seen=a["last"],
                wifi_in=a["wifi_in"], wifi_out=a["wifi_out"],
                wwan_in=a["wwan_in"], wwan_out=a["wwan_out"],
                wired_in=a["wired_in"], wired_out=a["wired_out"],
                rows=a["rows"], source=path)
            pu.notable = _flags.flag(pu)
            res.processes.append(pu)

        if "ZNETWORKATTACHMENT" in tables:
            acols = {r[1] for r in con.execute(
                "PRAGMA table_info(ZNETWORKATTACHMENT)")}
            ident = _col(acols, "ZIDENTIFIER", "ZNAME")
            kind = _col(acols, "ZKIND", "ZTYPE")
            first = _col(acols, "ZFIRSTTIMESTAMP")
            last = _col(acols, "ZTIMESTAMP")
            if ident:
                for r in con.execute(
                        f'SELECT "{ident}" AS i'
                        + (f', "{kind}" AS k' if kind else ', NULL AS k')
                        + (f', "{first}" AS f' if first else ', NULL AS f')
                        + (f', "{last}" AS l' if last else ', NULL AS l')
                        + ' FROM ZNETWORKATTACHMENT'):
                    res.attachments.append(Attachment(
                        identifier=str(r["i"] or ""), kind=str(r["k"] or ""),
                        first_seen=_utc(r["f"]), last_seen=_utc(r["l"])))

    res.processes.sort(key=lambda p: -p.total_out)
    return res
