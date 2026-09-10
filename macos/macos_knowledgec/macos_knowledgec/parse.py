"""Query the ZOBJECT stream out of knowledgeC.db."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from macos_knowledgec import flags as _flags
from macos_knowledgec.dbopen import connect

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

STREAMS = {
    "/app/usage": "app usage",
    "/app/inFocus": "app in focus",
    "/app/activity": "app activity",
    "/app/webUsage": "web usage",
    "/safari/history": "Safari history",
    "/app/mediaUsage": "media usage",
    "/app/intents": "Siri / Shortcuts intent",
    "/app/locationActivity": "location activity",
    "/notification/usage": "notification",
    "/display/isBacklit": "screen backlit",
    "/device/isLocked": "device locked",
    "/device/isPluggedIn": "device plugged in",
    "/device/batteryPercentage": "battery %",
    "/app/install": "app install",
    "/portrait/topic": "portrait topic",
}
_DEFAULT_STREAMS = ("/app/usage", "/app/inFocus", "/app/webUsage",
                    "/safari/history", "/app/intents", "/display/isBacklit",
                    "/app/mediaUsage", "/notification/usage", "/app/install")


def _utc(v) -> str:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return ""
    if f <= 0:
        return ""
    try:
        return (_MAC_EPOCH + timedelta(seconds=f)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Event:
    stream: str
    stream_raw: str
    value: str
    title: str
    start: str
    end: str
    duration_s: int
    device_id: str
    gmt_offset: int
    bundle_id: str
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "start": self.start, "end": self.end,
            "duration_s": self.duration_s, "stream": self.stream,
            "stream_raw": self.stream_raw, "value": self.value,
            "title": self.title, "bundle_id": self.bundle_id,
            "device_id": self.device_id, "gmt_offset": self.gmt_offset,
            "source": self.source, "notable": ";".join(self.notable),
        }


def parse(path: str, streams=None) -> list[Event]:
    want = set(streams) if streams else set(_DEFAULT_STREAMS)
    out: list[Event] = []
    with connect(path) as con:
        con.row_factory = sqlite3.Row
        try:
            zcols = {r[1] for r in con.execute("PRAGMA table_info(ZOBJECT)")}
        except sqlite3.Error:
            return out
        if not zcols:
            return out
        has_source = "ZSOURCE" in {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        has_meta = "ZSTRUCTUREDMETADATA" in {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}

        title_expr = "NULL"
        if has_meta:
            mcols = {r[1] for r in con.execute(
                "PRAGMA table_info(ZSTRUCTUREDMETADATA)")}
            for cand in ("Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE",
                         "Z_DKINTENTMETADATAKEY__INTENTCLASS",
                         "ZDKAPPLICATIONACTIVITYMETADATAKEY__TITLE"):
                if cand in mcols:
                    title_expr = f'M."{cand}"'
                    break

        dev_expr = 'S."ZDEVICEID"' if (has_source) else "NULL"
        joins = ""
        if has_source and "ZSOURCE" in zcols:
            joins += " LEFT JOIN ZSOURCE S ON S.Z_PK = O.ZSOURCE"
        if has_meta and "ZSTRUCTUREDMETADATA" in zcols:
            joins += (" LEFT JOIN ZSTRUCTUREDMETADATA M ON "
                      "M.Z_PK = O.ZSTRUCTUREDMETADATA")

        q = (f'SELECT O.ZSTREAMNAME AS stream, O.ZVALUESTRING AS val, '
             f'O.ZSTARTDATE AS s, O.ZENDDATE AS e, '
             f'O.ZSECONDSFROMGMT AS gmt, {dev_expr} AS dev, '
             f'{title_expr} AS title '
             f'FROM ZOBJECT O{joins} ORDER BY O.ZSTARTDATE')
        try:
            rows = con.execute(q).fetchall()
        except sqlite3.Error:
            # minimal fallback
            rows = con.execute(
                "SELECT ZSTREAMNAME AS stream, ZVALUESTRING AS val, "
                "ZSTARTDATE AS s, ZENDDATE AS e, ZSECONDSFROMGMT AS gmt, "
                "NULL AS dev, NULL AS title FROM ZOBJECT "
                "ORDER BY ZSTARTDATE").fetchall()

        for r in rows:
            sn = r["stream"] or ""
            if want and sn not in want:
                continue
            start = _utc(r["s"])
            end = _utc(r["e"])
            dur = 0
            try:
                if r["s"] and r["e"]:
                    dur = max(0, int(float(r["e"]) - float(r["s"])))
            except (TypeError, ValueError):
                dur = 0
            val = str(r["val"] or "")
            e = Event(
                stream=STREAMS.get(sn, sn), stream_raw=sn, value=val,
                title=str(r["title"] or ""), start=start, end=end,
                duration_s=dur, device_id=str(r["dev"] or ""),
                gmt_offset=int(r["gmt"]) if r["gmt"] is not None else 0,
                bundle_id=val if sn.startswith("/app/") and "." in val
                else "", source=path)
            e.notable = _flags.flag(e)
            out.append(e)
    out.sort(key=lambda x: x.start or "")
    return out
