"""Synthetic wpndatabase.db for the windows_notifications test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt):
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


TOAST = ('<toast><visual><binding template="ToastGeneric">'
         '<text>{title}</text><text>{body}</text>'
         '</binding></visual></toast>')


def build(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE NotificationHandler (
        RecordId INTEGER PRIMARY KEY, PrimaryId TEXT, HandlerType TEXT,
        CreatedTime INTEGER)""")
    con.execute("""CREATE TABLE Notification (
        Id INTEGER PRIMARY KEY, HandlerId INTEGER, Type INTEGER,
        Payload BLOB, PayloadType TEXT, Tag TEXT, "Group" TEXT,
        ExpiryTime INTEGER, ArrivalTime INTEGER, BootId INTEGER)""")

    con.executemany("INSERT INTO NotificationHandler VALUES (?,?,?,?)", [
        (1, "Microsoft.Windows.Explorer", "toast", 0),
        (2, "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell"
            "\\v1.0\\powershell.exe", "toast", 0),
        (3, "C:\\Users\\victim\\AppData\\Local\\Temp\\agent.exe", "toast", 0),
        (4, "Microsoft.SkypeApp_kzf8qxf38zg5c!App", "toast", 0),
    ])

    base = datetime(2026, 3, 9, 9, 0, tzinfo=timezone.utc)
    con.executemany(
        'INSERT INTO Notification VALUES (?,?,?,?,?,?,?,?,?,?)', [
            (1, 1, 1,
             TOAST.format(title="Download complete",
                          body="setup.exe finished downloading").encode(),
             "xml", "dl", "", ft(base.replace(hour=20)), ft(base), 1),
            (2, 2, 1,
             TOAST.format(title="Update",
                          body="visit http://185.10.20.30/patch to continue")
             .encode(), "xml", "", "", 0, ft(base.replace(minute=15)), 1),
            (3, 3, 4, b"\x00\x01\x02opaque-raw-payload\xff", "raw", "beacon",
             "", 0, ft(base.replace(minute=30)), 1),
            (4, 4, 1,
             TOAST.format(title="Alice",
                          body="Your login code is 550193").encode(),
             "xml", "im", "chat", ft(base.replace(hour=10)),
             ft(base.replace(minute=45)), 1),
        ])
    con.commit()
    con.close()
    return path
