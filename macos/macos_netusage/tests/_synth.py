"""Synthetic netusage.sqlite for the macos_netusage test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac(dt):
    return (dt.replace(tzinfo=timezone.utc) - _MAC_EPOCH).total_seconds()


def build(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE ZPROCESS (
        Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZBUNDLENAME TEXT,
        ZFIRSTTIMESTAMP REAL, ZTIMESTAMP REAL)""")
    con.execute("""CREATE TABLE ZLIVEUSAGE (
        Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZTIMESTAMP REAL,
        ZWIFIIN INTEGER, ZWIFIOUT INTEGER, ZWWANIN INTEGER, ZWWANOUT INTEGER,
        ZWIREDIN INTEGER, ZWIREDOUT INTEGER)""")
    con.execute("""CREATE TABLE ZNETWORKATTACHMENT (
        Z_PK INTEGER PRIMARY KEY, ZIDENTIFIER TEXT, ZKIND INTEGER,
        ZFIRSTTIMESTAMP REAL, ZTIMESTAMP REAL)""")

    base = datetime(2026, 3, 15, 9, 0)
    procs = [
        (1, "com.apple.Safari", "Safari"),
        (2, "curl", ""),
        (3, "/Users/victim/.cache/agent", ""),
        (4, "com.apple.mDNSResponder", ""),
        (5, "Spotify", "com.spotify.client"),
    ]
    for pk, name, bundle in procs:
        con.execute("INSERT INTO ZPROCESS VALUES (?,?,?,?,?)",
                    (pk, name, bundle, mac(base), mac(base.replace(hour=18))))

    # (pk, proc, ts_offset_h, wifi_in, wifi_out, wwan_in, wwan_out, wired_in,
    #  wired_out)
    usage = [
        (10, 1, 0, 40_000_000, 2_000_000, 0, 0, 0, 0),
        (11, 1, 3, 30_000_000, 1_500_000, 0, 0, 0, 0),
        (12, 2, 1, 20_000, 9_000_000, 0, 0, 0, 0),
        (13, 3, 2, 100_000, 250_000_000, 0, 0, 0, 0),   # big egress
        (14, 3, 4, 0, 3_000_000, 0, 2_000_000, 0, 0),   # + WWAN
        (15, 4, 0, 1_000, 1_000, 0, 0, 0, 0),
        (16, 5, 0, 500_000_000, 800_000, 0, 0, 0, 0),   # download-heavy
    ]
    for pk, proc, h, wi, wo, wwi, wwo, wdi, wdo in usage:
        con.execute("INSERT INTO ZLIVEUSAGE VALUES (?,?,?,?,?,?,?,?,?)",
                    (pk, proc, mac(base.replace(hour=9 + h)),
                     wi, wo, wwi, wwo, wdi, wdo))

    con.executemany("INSERT INTO ZNETWORKATTACHMENT VALUES (?,?,?,?,?)", [
        (1, "CorpWiFi", 1, mac(base), mac(base.replace(hour=17))),
        (2, "iPhone Hotspot", 2, mac(base.replace(hour=13)),
         mac(base.replace(hour=14))),
    ])
    con.commit()
    con.close()
    return path
