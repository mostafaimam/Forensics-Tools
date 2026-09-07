"""Build real synthetic browser SQLite stores for the test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_E1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)
_E2001 = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def chrome_us(s: str) -> int:
    return int((_dt(s) - _E1601).total_seconds() * 1_000_000)


def firefox_us(s: str) -> int:
    return int((_dt(s) - _E1970).total_seconds() * 1_000_000)


def cocoa_s(s: str) -> float:
    return (_dt(s) - _E2001).total_seconds()


# --------------------------------------------------------------------------
# Chromium History
# --------------------------------------------------------------------------

def chrome_history(path, *, visits, downloads=(), searches=()):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER,
            hidden INTEGER DEFAULT 0);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER,
            visit_time INTEGER, from_visit INTEGER, transition INTEGER,
            segment_id INTEGER, visit_duration INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT,
            current_path TEXT, target_path TEXT, start_time INTEGER,
            received_bytes INTEGER, total_bytes INTEGER, state INTEGER,
            danger_type INTEGER, interrupt_reason INTEGER, end_time INTEGER,
            referrer TEXT, tab_url TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER,
            url TEXT);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER,
            term TEXT, normalized_term TEXT);
    """)
    uid = {}
    vid = 1
    for i, v in enumerate(visits, 1):
        url = v["url"]
        if url not in uid:
            uid[url] = len(uid) + 1
            con.execute("INSERT INTO urls VALUES(?,?,?,?,?,?,0)",
                        (uid[url], url, v.get("title", ""),
                         v.get("visit_count", 1),
                         1 if v.get("transition") in (1, 5, 9, 10) else 0,
                         chrome_us(v["time"])))
        con.execute("INSERT INTO visits VALUES(?,?,?,?,?,0,0)",
                    (vid, uid[url], chrome_us(v["time"]),
                     v.get("from_visit", 0), v.get("transition", 0)))
        vid += 1
    for i, d in enumerate(downloads, 1):
        con.execute(
            "INSERT INTO downloads VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?,?)",
            (i, f"g{i}", d.get("target", ""), d.get("target", ""),
             chrome_us(d["time"]), d.get("bytes", 0), d.get("total", 0),
             d.get("state", 1), d.get("danger", 0),
             chrome_us(d.get("end", d["time"])), d.get("referrer", ""),
             d.get("tab_url", ""), d.get("mime", "")))
        con.execute("INSERT INTO downloads_url_chains VALUES(?,0,?)",
                    (i, d["url"]))
    for kid, s in enumerate(searches, 1):
        url = s["url"]
        if url not in uid:
            uid[url] = len(uid) + 1
            con.execute("INSERT INTO urls VALUES(?,?,?,1,1,?,0)",
                        (uid[url], url, "", chrome_us(s["time"])))
        con.execute("INSERT INTO keyword_search_terms VALUES(?,?,?,?)",
                    (kid, uid[url], s["term"], s["term"].lower()))
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------
# Firefox places.sqlite
# --------------------------------------------------------------------------

def firefox_places(path, *, visits, downloads=(), inputs=()):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER,
            frecency INTEGER, last_visit_date INTEGER, guid TEXT);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,
            from_visit INTEGER, place_id INTEGER, visit_date INTEGER,
            visit_type INTEGER, session INTEGER);
        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER,
            anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER);
        CREATE TABLE moz_inputhistory(place_id INTEGER, input TEXT,
            use_count REAL);
    """)
    pid = {}
    hv = 1
    for v in visits:
        url = v["url"]
        if url not in pid:
            pid[url] = len(pid) + 1
            con.execute("INSERT INTO moz_places VALUES(?,?,?,?,?,0,?,100,?,?)",
                        (pid[url], url, v.get("title", ""), "",
                         v.get("visit_count", 1),
                         1 if v.get("visit_type") == 2 else 0,
                         firefox_us(v["time"]), f"guid{pid[url]}"))
        con.execute("INSERT INTO moz_historyvisits VALUES(?,?,?,?,?,0)",
                    (hv, v.get("from_visit", 0), pid[url],
                     firefox_us(v["time"]), v.get("visit_type", 1)))
        hv += 1
    con.execute("INSERT INTO moz_anno_attributes VALUES(1,"
                "'downloads/destinationFileURI')")
    con.execute("INSERT INTO moz_anno_attributes VALUES(2,"
                "'downloads/metaData')")
    aid = 1
    for d in downloads:
        url = d["url"]
        if url not in pid:
            pid[url] = len(pid) + 1
            con.execute("INSERT INTO moz_places VALUES(?,?,?,?,1,0,0,100,?,?)",
                        (pid[url], url, "", "", firefox_us(d["time"]),
                         f"g{pid[url]}"))
        con.execute("INSERT INTO moz_annos VALUES(?,?,1,?,?)",
                    (aid, pid[url], "file:///" + d.get("target", ""),
                     firefox_us(d["time"])))
        aid += 1
        con.execute("INSERT INTO moz_annos VALUES(?,?,2,?,?)",
                    (aid, pid[url],
                     '{"fileSize":%d,"state":1}' % d.get("bytes", 0),
                     firefox_us(d["time"])))
        aid += 1
    for i in inputs:
        url = i.get("url", "")
        if url and url not in pid:
            pid[url] = len(pid) + 1
            con.execute("INSERT INTO moz_places VALUES(?,?,'','',1,0,1,1,0,?)",
                        (pid[url], url, f"g{pid[url]}"))
        con.execute("INSERT INTO moz_inputhistory VALUES(?,?,1.0)",
                    (pid.get(url, 0), i["input"]))
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------
# Safari History.db
# --------------------------------------------------------------------------

def safari_history(path, *, visits):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT,
            domain_expansion TEXT, visit_count INTEGER);
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY,
            history_item INTEGER, visit_time REAL, title TEXT,
            load_successful INTEGER, http_non_get INTEGER,
            redirect_source INTEGER, redirect_destination INTEGER,
            origin INTEGER);
    """)
    hid = {}
    vid = 1
    for v in visits:
        url = v["url"]
        if url not in hid:
            hid[url] = len(hid) + 1
            con.execute("INSERT INTO history_items VALUES(?,?,'',?)",
                        (hid[url], url, v.get("visit_count", 1)))
        con.execute("INSERT INTO history_visits VALUES(?,?,?,?,1,0,?,?,0)",
                    (vid, hid[url], cocoa_s(v["time"]), v.get("title", ""),
                     v.get("redirect_source"), v.get("redirect_destination")))
        vid += 1
    con.commit()
    con.close()
    return path
