"""Synthetic Chromium Bookmarks JSON + Firefox moz_bookmarks."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_E1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt):
    return str(int((dt - _E1601).total_seconds() * 1_000_000))


def ff_us(dt):
    return int((dt - _E1970).total_seconds() * 1_000_000)


def _url_node(name, url, added, modified=None, guid=None):
    return {
        "type": "url", "name": name, "url": url,
        "date_added": chrome_us(added),
        "date_modified": chrome_us(modified or added),
        "guid": guid or f"g-{name}",
    }


def _folder(name, children):
    return {"type": "folder", "name": name, "children": children}


def chromium_bookmarks(path: Path, *, bar=(), other=(), bak_bar=None):
    def nodes(items):
        return [_url_node(*it) if not isinstance(it, dict) else it
                for it in items]

    obj = {
        "checksum": "abc",
        "version": 1,
        "roots": {
            "bookmark_bar": {"name": "Bookmarks bar", "children": nodes(bar)},
            "other": {"name": "Other bookmarks", "children": nodes(other)},
            "synced": {"name": "Mobile bookmarks", "children": []},
        },
    }
    Path(path).write_text(json.dumps(obj), encoding="utf-8")
    if bak_bar is not None:
        bobj = json.loads(json.dumps(obj))
        bobj["roots"]["bookmark_bar"]["children"] = nodes(bak_bar)
        Path(str(path) + ".bak").write_text(json.dumps(bobj), encoding="utf-8")


def firefox_bookmarks(path: Path, entries):
    """entries: {folder, title, url, added, modified}"""
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT);
      CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER,
        parent INTEGER, position INTEGER, title TEXT, fk INTEGER,
        dateAdded INTEGER, lastModified INTEGER, guid TEXT);
    """)
    # root(1) -> toolbar(2)
    con.execute("INSERT INTO moz_bookmarks VALUES (1,2,0,0,NULL,NULL,0,0,'root')")
    con.execute("INSERT INTO moz_bookmarks VALUES "
                "(2,2,1,0,'toolbar',NULL,0,0,'tbar')")
    folders = {"toolbar": 2}
    nid = 3
    pid = 100
    for e in entries:
        parent = folders.get(e.get("folder", "toolbar"))
        if parent is None:
            con.execute("INSERT INTO moz_bookmarks VALUES "
                        "(?,2,2,0,?,NULL,0,0,?)",
                        (nid, e["folder"], f"f{nid}"))
            folders[e["folder"]] = parent = nid
            nid += 1
        con.execute("INSERT INTO moz_places VALUES (?,?)", (pid, e["url"]))
        con.execute("INSERT INTO moz_bookmarks VALUES (?,1,?,0,?,?,?,?,?)",
                    (nid, parent, e["title"], pid,
                     ff_us(e["added"]),
                     ff_us(e.get("modified", e["added"])), f"g{nid}"))
        nid += 1
        pid += 1
    con.commit()
    con.close()
