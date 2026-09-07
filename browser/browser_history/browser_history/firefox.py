"""Firefox / Tor Browser ``places.sqlite`` (+ legacy ``downloads.sqlite``)."""

from __future__ import annotations

import json
from pathlib import Path

from browser_history import timeconv as _t
from browser_history.dbopen import connect, has_table, query
from browser_history.model import Download, SearchTerm, Visit

_VISIT_TYPE = {
    1: ("link", False), 2: ("typed", True), 3: ("bookmark", False),
    4: ("embed", False), 5: ("redirect", False), 6: ("redirect", False),
    7: ("download", False), 8: ("link", False), 9: ("reload", False),
}


def looks_like(path: Path) -> bool:
    return path.name == "places.sqlite"


def parse(db_path: str, browser: str, profile: str) -> list:
    out: list = []
    p = str(db_path)
    with connect(p) as con:
        if not has_table(con, "moz_places"):
            return out
        places = {r["id"]: r for r in query(
            con, "SELECT id, url, title, visit_count, typed FROM moz_places")}

        if has_table(con, "moz_historyvisits"):
            id_url = {i: r["url"] for i, r in places.items()}
            visit_place = {r["id"]: r["place_id"] for r in query(
                con, "SELECT id, place_id FROM moz_historyvisits")}
            for r in query(con,
                           "SELECT place_id, visit_date, from_visit, visit_type "
                           "FROM moz_historyvisits ORDER BY visit_date"):
                pl = places.get(r["place_id"])
                if not pl:
                    continue
                label, typed = _VISIT_TYPE.get(int(r["visit_type"] or 1),
                                               ("link", False))
                frm = id_url.get(visit_place.get(r["from_visit"]), "")
                out.append(Visit(
                    browser=browser, profile=profile, url=pl["url"],
                    title=pl["title"] or "",
                    visit_time=_t.webkit_us(r["visit_date"]),
                    visit_count=pl["visit_count"] or 0,
                    typed=typed or bool(pl["typed"]),
                    transition=label, from_url=frm, source_db=p))
        else:
            for pl in places.values():
                out.append(Visit(
                    browser=browser, profile=profile, url=pl["url"],
                    title=pl["title"] or "", visit_time="",
                    visit_count=pl["visit_count"] or 0,
                    typed=bool(pl["typed"]), transition="link", source_db=p))

        # search terms: moz_inputhistory (typed-into-urlbar) + keyword table
        if has_table(con, "moz_inputhistory"):
            for r in query(con,
                           "SELECT h.input AS term, p.url AS url "
                           "FROM moz_inputhistory h JOIN moz_places p "
                           "ON p.id = h.place_id"):
                if r["term"]:
                    out.append(SearchTerm(
                        browser=browser, profile=profile, term=r["term"],
                        url=r["url"] or "", time="", source_db=p))

        # downloads: modern Firefox annotates the place with the destination
        if has_table(con, "moz_annos") and has_table(con,
                                                     "moz_anno_attributes"):
            dest = {}
            meta = {}
            for r in query(con,
                           "SELECT a.place_id AS pid, n.name AS name, "
                           "a.content AS content, a.dateAdded AS d "
                           "FROM moz_annos a JOIN moz_anno_attributes n "
                           "ON n.id = a.anno_attribute_id "
                           "WHERE n.name LIKE 'downloads/%'"):
                if r["name"] == "downloads/destinationFileURI":
                    dest[r["pid"]] = (r["content"], r["d"])
                elif r["name"] == "downloads/metaData":
                    meta[r["pid"]] = r["content"]
            for pid, (uri, d) in dest.items():
                pl = places.get(pid)
                if not pl:
                    continue
                size = 0
                state = ""
                try:
                    m = json.loads(meta.get(pid, "{}"))
                    size = int(m.get("fileSize") or 0)
                    state = str(m.get("state", ""))
                except Exception:  # noqa: BLE001
                    pass
                out.append(Download(
                    browser=browser, profile=profile, url=pl["url"],
                    referrer="", tab_url="",
                    target_path=(uri or "").replace("file:///", "").replace(
                        "%20", " "),
                    start_time=_t.webkit_us(d), end_time="",
                    bytes=size, total_bytes=size, state=state or "complete",
                    danger="", mime="", source_db=p))
    return out


def parse_legacy_downloads(db_path: str, browser: str, profile: str) -> list:
    out: list = []
    p = str(db_path)
    with connect(p) as con:
        if not has_table(con, "moz_downloads"):
            return out
        for r in query(con, "SELECT * FROM moz_downloads"):
            d = dict(r)
            out.append(Download(
                browser=browser, profile=profile, url=d.get("source", "") or "",
                referrer=d.get("referrer", "") or "", tab_url="",
                target_path=(d.get("target", "") or "").replace(
                    "file:///", ""),
                start_time=_t.webkit_us(d.get("startTime")),
                end_time=_t.webkit_us(d.get("endTime")),
                bytes=d.get("currBytes") or 0, total_bytes=d.get("maxBytes")
                or 0, state=str(d.get("state", "")), danger="",
                mime=d.get("mimeType", "") or "", source_db=p))
    return out
