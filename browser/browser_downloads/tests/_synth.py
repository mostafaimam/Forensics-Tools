"""Build synthetic browser stores + a filesystem tree for the test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_E1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt: datetime) -> int:
    return int((dt - _E1601).total_seconds() * 1_000_000)


def webkit_us(dt: datetime) -> int:
    return int((dt - _E1970).total_seconds() * 1_000_000)


def chromium_history(path: Path, downloads: list[dict]) -> None:
    """downloads: {url, target, referrer, tab_url, start, end, received,
    total, state, danger, mime, chain=[urls], opened=bool}"""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE downloads (
          id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT,
          target_path TEXT, start_time INTEGER, received_bytes INTEGER,
          total_bytes INTEGER, state INTEGER, danger_type INTEGER,
          interrupt_reason INTEGER, end_time INTEGER, opened INTEGER,
          last_access_time INTEGER, referrer TEXT, site_url TEXT,
          tab_url TEXT, tab_referrer_url TEXT, mime_type TEXT,
          original_mime_type TEXT);
        CREATE TABLE downloads_url_chains (
          id INTEGER, chain_index INTEGER, url TEXT,
          PRIMARY KEY (id, chain_index));
    """)
    for i, d in enumerate(downloads, 1):
        con.execute(
            "INSERT INTO downloads (id, target_path, current_path, "
            "start_time, received_bytes, total_bytes, state, danger_type, "
            "interrupt_reason, end_time, opened, last_access_time, referrer, "
            "tab_url, mime_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (i, d["target"], d["target"],
             chrome_us(d["start"]), d.get("received", 0), d.get("total", 0),
             d.get("state", 1), d.get("danger", 0), d.get("interrupt", 0),
             chrome_us(d["end"]) if d.get("end") else 0,
             1 if d.get("opened") else 0,
             chrome_us(d["end"]) if d.get("opened") and d.get("end") else 0,
             d.get("referrer", ""), d.get("tab_url", ""), d.get("mime", "")))
        chain = d.get("chain") or [d["url"]]
        for ci, u in enumerate(chain):
            con.execute("INSERT INTO downloads_url_chains VALUES (?,?,?)",
                        (i, ci, u))
    con.commit()
    con.close()


def firefox_places(path: Path, downloads: list[dict]) -> None:
    """downloads: {url, dest (file:// URI or path), added, modified, size,
    state}"""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT,
          title TEXT, visit_count INTEGER, typed INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER,
          anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER,
          lastModified INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY,
          place_id INTEGER, visit_date INTEGER, from_visit INTEGER,
          visit_type INTEGER);
    """)
    con.execute("INSERT INTO moz_anno_attributes VALUES "
                "(1,'downloads/destinationFileURI')")
    con.execute("INSERT INTO moz_anno_attributes VALUES "
                "(2,'downloads/metaData')")
    for i, d in enumerate(downloads, 1):
        con.execute("INSERT INTO moz_places VALUES (?,?,?,?,?)",
                    (i, d["url"], "", 1, 0))
        con.execute("INSERT INTO moz_annos (place_id, anno_attribute_id, "
                    "content, dateAdded, lastModified) VALUES (?,1,?,?,?)",
                    (i, d["dest"], webkit_us(d["added"]),
                     webkit_us(d.get("modified", d["added"]))))
        meta = ('{"state":%d,"fileSize":%d}'
                % (d.get("state", 1), d.get("size", 0)))
        con.execute("INSERT INTO moz_annos (place_id, anno_attribute_id, "
                    "content, dateAdded, lastModified) VALUES (?,2,?,?,?)",
                    (i, meta, webkit_us(d["added"]),
                     webkit_us(d.get("modified", d["added"]))))
    con.commit()
    con.close()


def zone_identifier(target: Path, *, zone_id="3", host="", referrer="") -> Path:
    body = "[ZoneTransfer]\r\nZoneId=%s\r\n" % zone_id
    if referrer:
        body += "ReferrerUrl=%s\r\n" % referrer
    if host:
        body += "HostUrl=%s\r\n" % host
    z = target.with_name(target.name + ":Zone.Identifier")
    # ':' is illegal in filenames on Windows - use the extracted-tree form
    z = target.with_name(target.name + "_Zone.Identifier")
    z.write_text(body, encoding="utf-8")
    return z
