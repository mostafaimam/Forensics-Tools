"""Firefox / Tor Browser downloads (places.sqlite annos + legacy DB)."""

from __future__ import annotations

import json
from pathlib import Path

from browser_downloads import timeconv as _t
from browser_downloads.dbopen import connect, has_table, query
from browser_downloads.model import Download

_FF_STATE = {
    -1: "unknown", 0: "downloading", 1: "complete", 2: "failed",
    3: "cancelled", 4: "paused", 5: "queued", 6: "blocked-parental",
    7: "scanning", 8: "dirty", 9: "blocked-policy",
}


def _profile(p: str) -> str:
    for seg in reversed(Path(p).parts[:-1]):
        if ".default" in seg or "profile" in seg.lower():
            return seg
    return ""


def _unfile(uri: str) -> str:
    return (uri or "").replace("file:///", "").replace("file://", "").replace(
        "%20", " ")


def parse(db_path: str) -> list[Download]:
    out: list[Download] = []
    p = str(db_path)
    prof = _profile(p)
    with connect(p) as con:
        if not (has_table(con, "moz_annos")
                and has_table(con, "moz_anno_attributes")):
            return out
        places = {r["id"]: r["url"] for r in query(
            con, "SELECT id, url FROM moz_places")}
        dest: dict = {}
        meta: dict = {}
        for r in query(con,
                       "SELECT a.place_id AS pid, n.name AS name, "
                       "a.content AS content, a.dateAdded AS da, "
                       "a.lastModified AS lm "
                       "FROM moz_annos a JOIN moz_anno_attributes n "
                       "ON n.id = a.anno_attribute_id "
                       "WHERE n.name LIKE 'downloads/%'"):
            if r["name"] == "downloads/destinationFileURI":
                dest[r["pid"]] = (r["content"], r["da"], r["lm"])
            elif r["name"] == "downloads/metaData":
                meta[r["pid"]] = r["content"]
        for pid, (uri, da, lm) in dest.items():
            url = places.get(pid, "")
            size = tot = 0
            state = ""
            try:
                m = json.loads(meta.get(pid, "{}"))
                size = int(m.get("fileSize") or m.get("currBytes") or 0)
                tot = int(m.get("fileSize") or m.get("maxBytes") or 0)
                state = _FF_STATE.get(m.get("state"), str(m.get("state", "")))
            except (ValueError, TypeError):
                pass
            out.append(Download(
                browser="Firefox", profile=prof, source="history-db",
                url=url, target_path=_unfile(uri),
                start_time=_t.webkit_us(da), end_time=_t.webkit_us(lm),
                received_bytes=size, total_bytes=tot,
                state=state or "complete", source_db=p))
    return out


def parse_legacy(db_path: str) -> list[Download]:
    out: list[Download] = []
    p = str(db_path)
    prof = _profile(p)
    with connect(p) as con:
        if not has_table(con, "moz_downloads"):
            return out
        for r in query(con, "SELECT * FROM moz_downloads"):
            d = dict(r)
            out.append(Download(
                browser="Firefox", profile=prof, source="history-db",
                url=d.get("source", "") or "",
                referrer=d.get("referrer", "") or "",
                target_path=_unfile(d.get("target", "")),
                start_time=_t.webkit_us(d.get("startTime")),
                end_time=_t.webkit_us(d.get("endTime")),
                received_bytes=d.get("currBytes") or 0,
                total_bytes=d.get("maxBytes") or 0,
                state=_FF_STATE.get(d.get("state"), str(d.get("state", ""))),
                mime=d.get("mimeType", "") or "", source_db=p))
    return out
