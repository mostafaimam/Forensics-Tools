"""Synthetic Chromium Login Data + Firefox logins.json for the test-suite."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt):
    return int((dt - _E1601).total_seconds() * 1_000_000)


def ms(dt):
    return int(dt.timestamp() * 1000)


def login_data(path: Path, rows):
    """rows: {origin, realm, username, user_elem, created, last_used,
    pw_changed, times, blacklisted, has_pw}"""
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE logins (
        origin_url TEXT, action_url TEXT, username_element TEXT,
        username_value TEXT, password_element TEXT, password_value BLOB,
        signon_realm TEXT, date_created INTEGER, date_last_used INTEGER,
        date_password_modified INTEGER, times_used INTEGER,
        blacklisted_by_user INTEGER, scheme INTEGER)""")
    for r in rows:
        con.execute("INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (r["origin"], r.get("action", r["origin"]),
                     r.get("user_elem", "username"), r.get("username", ""),
                     "password",
                     (b"\x01" * 60) if r.get("has_pw", True) else b"",
                     r.get("realm", r["origin"]),
                     chrome_us(r["created"]),
                     chrome_us(r["last_used"]) if r.get("last_used") else 0,
                     chrome_us(r["pw_changed"]) if r.get("pw_changed") else 0,
                     r.get("times", 0), 1 if r.get("blacklisted") else 0, 0))
    con.commit()
    con.close()


def firefox_logins(path: Path, logins, disabled=(), primary_password=False):
    obj = {
        "nextId": len(logins) + 1,
        "logins": [
            {
                "id": i + 1,
                "hostname": lg["hostname"],
                "httpRealm": lg.get("realm"),
                "formSubmitURL": lg.get("form_url", ""),
                "usernameField": lg.get("user_field", "username"),
                "passwordField": "password",
                "encryptedUsername": lg.get("enc_user", "MEIEEPgAAAAAAAAAAAAAAAAAAAE="),
                "encryptedPassword": lg.get("enc_pw", "MEIEEPgAAAAAAAAAAAAAAAAAAAE="),
                "timeCreated": ms(lg["created"]),
                "timeLastUsed": ms(lg["last_used"]) if lg.get("last_used")
                else 0,
                "timePasswordChanged": ms(lg["pw_changed"])
                if lg.get("pw_changed") else ms(lg["created"]),
                "timesUsed": lg.get("times", 0),
            }
            for i, lg in enumerate(logins)
        ],
        "disabledHosts": list(disabled),
        "version": 3,
    }
    Path(path).write_text(json.dumps(obj), encoding="utf-8")
    if primary_password:
        _key4(Path(path).with_name("key4.db"), primary=True)
    else:
        _key4(Path(path).with_name("key4.db"), primary=False)


def _key4(path: Path, *, primary: bool):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, "
                "item2 BLOB)")
    item2 = (b"\x00" * 60) if primary else (b"\x00" * 20)
    con.execute("INSERT INTO metadata VALUES ('password', ?, ?)",
                (b"\x00" * 16, item2))
    con.commit()
    con.close()
