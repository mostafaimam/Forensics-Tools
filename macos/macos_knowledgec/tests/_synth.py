"""Synthetic knowledgeC.db for the macos_knowledgec test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac(dt):
    return (dt.replace(tzinfo=timezone.utc) - _MAC_EPOCH).total_seconds()


def build(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE ZSOURCE (
        Z_PK INTEGER PRIMARY KEY, ZDEVICEID TEXT)""")
    con.execute("""CREATE TABLE ZSTRUCTUREDMETADATA (
        Z_PK INTEGER PRIMARY KEY,
        "Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE" TEXT)""")
    con.execute("""CREATE TABLE ZOBJECT (
        Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
        ZSTARTDATE REAL, ZENDDATE REAL, ZSECONDSFROMGMT INTEGER,
        ZSOURCE INTEGER, ZSTRUCTUREDMETADATA INTEGER)""")

    con.execute("INSERT INTO ZSOURCE VALUES (1, 'MacBookPro18,3')")
    con.execute("INSERT INTO ZSTRUCTUREDMETADATA VALUES (1, 'Q1 report.pages')")

    base = datetime(2026, 3, 12, 9, 0)

    def ev(pk, stream, val, start, dur, meta=None):
        return (pk, stream, val, mac(start),
                mac(start) + dur, -25200, 1, meta)

    con.executemany(
        "INSERT INTO ZOBJECT VALUES (?,?,?,?,?,?,?,?)", [
            ev(1, "/app/inFocus", "com.apple.Pages", base, 1800, 1),
            ev(2, "/app/usage", "com.apple.Terminal",
               base.replace(hour=10), 7200),
            ev(3, "/app/webUsage", "transfer.sh",
               base.replace(hour=11), 120),
            ev(4, "/display/isBacklit", "1", base.replace(hour=8, minute=55),
               21600),
            ev(5, "/device/isLocked", "0", base.replace(hour=8, minute=56),
               100),
            ev(6, "/app/intents", "Run Shell Script",
               base.replace(hour=12), 3),
            ev(7, "/app/usage", "com.spotify.client",
               base.replace(hour=23, minute=30), 1800),
            ev(8, "/app/install", "com.acme.tool",
               base.replace(hour=13), 0),
        ])
    con.commit()
    con.close()
    return path
