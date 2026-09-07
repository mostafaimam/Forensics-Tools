"""Build real synthetic cookie stores for the test-suite."""

from __future__ import annotations

import sqlite3
import struct
from datetime import datetime, timezone

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_E1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)
_E2001 = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def chrome_us(s: str) -> int:
    return int((_dt(s) - _E1601).total_seconds() * 1_000_000)


def unix_s(s: str) -> int:
    return int((_dt(s) - _E1970).total_seconds())


def unix_us(s: str) -> int:
    return int((_dt(s) - _E1970).total_seconds() * 1_000_000)


def cocoa_s(s: str) -> float:
    return (_dt(s) - _E2001).total_seconds()


# --------------------------------------------------------------------------
# Chromium Cookies
# --------------------------------------------------------------------------

def chrome_cookies(path, cookies):
    con = sqlite3.connect(path)
    con.execute("""
        CREATE TABLE cookies(creation_utc INTEGER PRIMARY KEY, host_key TEXT,
            name TEXT, value TEXT, path TEXT, expires_utc INTEGER,
            is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER,
            has_expires INTEGER, is_persistent INTEGER, priority INTEGER,
            encrypted_value BLOB, samesite INTEGER, source_scheme INTEGER)
    """)
    for i, c in enumerate(cookies):
        exp = chrome_us(c["expires"]) if c.get("expires") else 0
        enc = b"v10" + b"\x00" * c.get("value_len", 24)
        con.execute("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,2)",
                    (chrome_us(c["created"]) + i, c["host"], c["name"], "",
                     c.get("path", "/"), exp, int(c.get("secure", 0)),
                     int(c.get("httponly", 0)),
                     chrome_us(c.get("last_access", c["created"])),
                     1 if exp else 0, 1 if exp else 0, enc,
                     c.get("samesite", 1)))
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------
# Firefox cookies.sqlite
# --------------------------------------------------------------------------

def firefox_cookies(path, cookies):
    con = sqlite3.connect(path)
    con.execute("""
        CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT,
            name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
            lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER,
            isHttpOnly INTEGER, inBrowserElement INTEGER, sameSite INTEGER,
            rawSameSite INTEGER, schemeMap INTEGER)
    """)
    for i, c in enumerate(cookies, 1):
        con.execute("INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,?,3)",
                    (i, "", c["name"], c.get("value", "x" * 20), c["host"],
                     c.get("path", "/"),
                     unix_s(c["expires"]) if c.get("expires") else 0,
                     unix_us(c.get("last_access", c["created"])),
                     unix_us(c["created"]), int(c.get("secure", 0)),
                     int(c.get("httponly", 0)), c.get("samesite", 1),
                     c.get("samesite", 1)))
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------
# Safari Cookies.binarycookies
# --------------------------------------------------------------------------

def _safari_cookie(host, name, path, value, expires, created, *, secure=False,
                   httponly=False):
    flags = (0x1 if secure else 0) | (0x4 if httponly else 0)
    header = 0x38
    strings = b""

    def add(s):
        nonlocal strings
        off = header + len(strings)
        strings += s.encode() + b"\x00"
        return off

    url_o = add("." + host if not host.startswith(".") else host)
    name_o = add(name)
    path_o = add(path)
    val_o = add(value)
    size = header + len(strings)
    size = (size + 3) & ~3
    blob = bytearray(size)
    struct.pack_into("<I", blob, 0x00, size)
    struct.pack_into("<I", blob, 0x08, flags)
    struct.pack_into("<IIII", blob, 0x10, url_o, name_o, path_o, val_o)
    struct.pack_into("<dd", blob, 0x28, expires, created)
    blob[header:header + len(strings)] = strings
    return bytes(blob)


def safari_cookies(path, cookies):
    blobs = [_safari_cookie(c["host"], c["name"], c.get("path", "/"),
                            c.get("value", "v"),
                            cocoa_s(c["expires"]) if c.get("expires") else 0.0,
                            cocoa_s(c["created"]),
                            secure=c.get("secure", False),
                            httponly=c.get("httponly", False))
             for c in cookies]
    n = len(blobs)
    page = bytearray(b"\x00\x00\x01\x00")
    page += struct.pack("<I", n)
    header_len = 4 + 4 + n * 4 + 4
    offs = []
    cur = header_len
    for b in blobs:
        offs.append(cur)
        cur += len(b)
    for o in offs:
        page += struct.pack("<I", o)
    page += b"\x00\x00\x00\x00"
    for b in blobs:
        page += b
    page_bytes = bytes(page)

    data = b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page_bytes))
    data += page_bytes
    data += struct.pack(">Q", 0) + b"\x00" * 4  # footer / checksum (ignored)
    with open(path, "wb") as fh:
        fh.write(data)
    return path
