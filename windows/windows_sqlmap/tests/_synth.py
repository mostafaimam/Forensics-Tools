"""Build small synthetic SQLite databases matching the built-in maps."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def build_skype(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE Conversations (id INTEGER PRIMARY KEY, "
               "identity TEXT)")
    con.execute("CREATE TABLE Messages (id INTEGER PRIMARY KEY, "
               "timestamp INTEGER, author TEXT, from_dispname TEXT, "
               "dialog_partner TEXT, chatname TEXT, body_xml TEXT, "
               "type INTEGER)")
    ts = int(datetime(2026, 3, 16, 9, 0, tzinfo=timezone.utc).timestamp())
    con.execute("INSERT INTO Messages VALUES (1,?,?,?,?,?,?,?)",
               (ts, "alice", "Alice", "bob", "alice/bob",
                "hey, still on for the call?", 61))
    con.execute("INSERT INTO Messages VALUES (2,?,?,?,?,?,?,?)",
               (ts + 60, "bob", "Bob", "alice", "alice/bob",
                "yep, 3pm works", 61))
    con.commit()
    con.close()


def build_sticky_notes(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE Note (Id TEXT, Text TEXT, CreatedAt INTEGER, "
               "LastModified INTEGER)")
    # FILETIME for 2026-03-16T09:30:00Z
    ft = int((datetime(2026, 3, 16, 9, 30, tzinfo=timezone.utc)
             - datetime(1601, 1, 1, tzinfo=timezone.utc)
             ).total_seconds() * 10_000_000)
    con.execute("INSERT INTO Note VALUES (?,?,?,?)",
               ("n1", "don't forget: rotate the API keys", ft - 6000000000,
                ft))
    con.commit()
    con.close()


def build_unknown(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE WidgetSettings (key TEXT, value TEXT)")
    con.execute("INSERT INTO WidgetSettings VALUES ('theme','dark')")
    con.execute("INSERT INTO WidgetSettings VALUES ('autosave','1')")
    con.commit()
    con.close()
