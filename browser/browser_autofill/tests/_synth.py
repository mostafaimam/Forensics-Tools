"""Synthetic Chromium Web Data + Firefox formhistory for the test-suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_E1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt):
    return int((dt - _E1601).total_seconds() * 1_000_000)


def ff_us(dt):
    return int((dt - _E1970).total_seconds() * 1_000_000)


def web_data(path: Path, *, fields=(), profiles=(), cards=()):
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT,
        date_created INTEGER, date_last_used INTEGER, count INTEGER);
      CREATE TABLE autofill_profiles (guid TEXT, company_name TEXT,
        street_address TEXT, city TEXT, state TEXT, zipcode TEXT,
        country_code TEXT, full_name TEXT, email TEXT, number TEXT,
        use_count INTEGER, use_date INTEGER, date_modified INTEGER);
      CREATE TABLE credit_cards (guid TEXT, name_on_card TEXT,
        expiration_month INTEGER, expiration_year INTEGER,
        card_number_encrypted BLOB, network TEXT, last_four TEXT,
        use_count INTEGER, use_date INTEGER);
    """)
    for name, value, created, last, count in fields:
        con.execute("INSERT INTO autofill VALUES (?,?,?,?,?,?)",
                    (name, value, value.lower(), chrome_us(created),
                     chrome_us(last), count))
    for pr in profiles:
        con.execute("INSERT INTO autofill_profiles (guid, full_name, "
                    "street_address, city, state, zipcode, country_code, "
                    "email, number, use_count, use_date) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ("g", pr.get("name", ""), pr.get("street", ""),
                     pr.get("city", ""), pr.get("state", ""),
                     pr.get("zip", ""), pr.get("cc", "US"),
                     pr.get("email", ""), pr.get("phone", ""),
                     pr.get("use_count", 1), chrome_us(pr["use_date"])))
    for cd in cards:
        con.execute("INSERT INTO credit_cards (guid, name_on_card, "
                    "expiration_month, expiration_year, last_four, network, "
                    "use_count, use_date) VALUES (?,?,?,?,?,?,?,?)",
                    ("c", cd.get("holder", ""), cd.get("month", 12),
                     cd.get("year", 2028), cd.get("last4", ""),
                     cd.get("network", "Visa"), cd.get("use_count", 1),
                     chrome_us(cd["use_date"])))
    con.commit()
    con.close()


def formhistory(path: Path, fields):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, "
                "fieldname TEXT, value TEXT, timesUsed INTEGER, "
                "firstUsed INTEGER, lastUsed INTEGER)")
    for i, (name, value, first, last, count) in enumerate(fields, 1):
        con.execute("INSERT INTO moz_formhistory VALUES (?,?,?,?,?,?)",
                    (i, name, value, count, ff_us(first), ff_us(last)))
    con.commit()
    con.close()
