"""Synthetic QuarantineEventsV2 for the macos_quarantine test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac(dt):
    return (dt.replace(tzinfo=timezone.utc) - _MAC_EPOCH).total_seconds()


def build(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE LSQuarantineEvent (
        LSQuarantineEventIdentifier TEXT PRIMARY KEY,
        LSQuarantineTimeStamp REAL,
        LSQuarantineAgentBundleIdentifier TEXT,
        LSQuarantineAgentName TEXT,
        LSQuarantineDataURLString TEXT,
        LSQuarantineTypeNumber INTEGER,
        LSQuarantineOriginTitle TEXT,
        LSQuarantineOriginURLString TEXT,
        LSQuarantineSenderName TEXT,
        LSQuarantineSenderAddress TEXT)""")
    base = datetime(2026, 3, 10, 9, 0)
    con.executemany(
        "INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?,?,?,?)", [
            ("A1", mac(base), "com.apple.Safari", "Safari",
             "https://cdn.example.com/report.pdf", 0, "Example",
             "https://example.com/reports", None, None),
            ("A2", mac(base.replace(hour=10)), "com.google.Chrome", "Chrome",
             "https://downloads.example.net/Installer.dmg", 0, "Get the app",
             "https://example.net/download", None, None),
            ("A3", mac(base.replace(hour=11)), "com.apple.Terminal",
             "Terminal", "http://185.10.20.30/payload.command", 2, "",
             "http://185.10.20.30/", None, None),
            ("A4", mac(base.replace(hour=12)), "com.apple.mail", "Mail",
             "cid:attachment/update.pkg", 1, "Invoice",
             "", "Bob Vendor", "bob@vendor.example"),
            ("A5", mac(base.replace(hour=13)), "org.mozilla.firefox",
             "Firefox", "https://transfer.sh/abc/tool.zip", 0, "",
             "https://transfer.sh/", None, None),
        ])
    con.commit()
    con.close()
    return path
