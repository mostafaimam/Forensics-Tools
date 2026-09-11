"""Build a tiny Core Data-shaped SQLite store (RMAdminStore-Local.sqlite)."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac_ts(dt: datetime) -> float:
    return (dt - _MAC_EPOCH).total_seconds()


def build(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, "
               "Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER)")
    con.execute("INSERT INTO Z_PRIMARYKEY VALUES (1, 'RMDAppUsage', 0, 0)")
    con.execute("INSERT INTO Z_PRIMARYKEY VALUES (2, 'RMDDevice', 0, 0)")

    con.execute("CREATE TABLE ZRMDAPPUSAGE (Z_PK INTEGER PRIMARY KEY, "
               "Z_ENT INTEGER, Z_OPT INTEGER, ZBUNDLEIDENTIFIER TEXT, "
               "ZTOTALTIME REAL, ZDATE REAL, ZDEVICEIDENTIFIER TEXT)")
    con.execute("CREATE TABLE ZRMDDEVICE (Z_PK INTEGER PRIMARY KEY, "
               "Z_ENT INTEGER, Z_OPT INTEGER, ZNAME TEXT, "
               "ZIDENTIFIER TEXT)")

    day1 = mac_ts(datetime(2026, 3, 15, 0, 0, tzinfo=timezone.utc))
    day2 = mac_ts(datetime(2026, 3, 16, 0, 0, tzinfo=timezone.utc))
    con.execute("INSERT INTO ZRMDAPPUSAGE VALUES (1,1,0,?,?,?,?)",
               ("com.apple.mobilesafari", 7200.0, day1, "iphone-abc"))
    con.execute("INSERT INTO ZRMDAPPUSAGE VALUES (2,1,0,?,?,?,?)",
               ("com.some.game", 21600.0, day2, "ipad-def"))
    con.execute("INSERT INTO ZRMDDEVICE VALUES (1,2,0,?,?)",
               ("Mostafa's iPhone", "iphone-abc"))
    con.commit()
    con.close()
