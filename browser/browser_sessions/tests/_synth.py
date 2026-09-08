"""Build a Chromium SNSS stream and a Firefox sessionstore for the tests."""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt):
    return int((dt - _E1601).total_seconds() * 1_000_000)


# --------------------------------------------------------------------------
# Chromium SNSS
# --------------------------------------------------------------------------

def _wint(v):
    return struct.pack("<i", v)


def _wstr(s):
    b = s.encode("utf-8")
    pad = (-len(b)) % 4
    return struct.pack("<I", len(b)) + b + b"\x00" * pad


def _wstr16(s):
    b = s.encode("utf-16-le")
    pad = (-len(b)) % 4
    return struct.pack("<I", len(s)) + b + b"\x00" * pad


def _wint64(v):
    return struct.pack("<q", v)


def _pickle(payload):
    return struct.pack("<I", len(payload)) + payload


def _command(cmd_id, content):
    body = bytes([cmd_id]) + content
    return struct.pack("<H", len(body)) + body


def snss(tabs, *, version=3):
    """tabs: list of dicts {tab_id, window, index, pinned, closed,
    last_active (datetime), entries=[(url,title), ...]}"""
    out = struct.pack("<ii", 0x53534E53, version)
    for t in tabs:
        tid = t["tab_id"]
        out += _command(0, struct.pack("<ii", t.get("window", 1), tid))
        out += _command(2, _pickle(_wint(tid) + _wint(t.get("index", 0))))
        for ei, (url, title) in enumerate(t.get("entries", [])):
            out += _command(6, _pickle(
                _wint(tid) + _wint(ei) + _wstr(url) + _wstr16(title)))
        if t.get("pinned"):
            out += _command(12, _pickle(_wint(tid) + _wint(1)))
        if t.get("last_active"):
            out += _command(21, _pickle(
                _wint(tid) + _wint64(chrome_us(t["last_active"]))))
        if t.get("closed"):
            out += _command(16, struct.pack("<iq", tid, 0))
    return out


# --------------------------------------------------------------------------
# Firefox sessionstore (plain + mozLz4)
# --------------------------------------------------------------------------

def _lz4_literals(data: bytes) -> bytes:
    out = bytearray()
    n = len(data)
    if n < 15:
        out.append(n << 4)
    else:
        out.append(0xF0)
        rem = n - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
    out += data
    return bytes(out)


def mozlz4(obj) -> bytes:
    raw = json.dumps(obj).encode("utf-8")
    return b"mozLz4a\x00" + struct.pack("<I", len(raw)) + _lz4_literals(raw)


def sessionstore_obj(windows, closed_windows=()):
    return {
        "version": ["sessionrestore", 1],
        "windows": windows,
        "_closedWindows": list(closed_windows),
        "selectedWindow": 1,
    }


def win(tabs, closed_tabs=(), selected=1):
    return {"tabs": tabs, "_closedTabs": list(closed_tabs), "selected": selected}


def tab(entries, *, index=None, pinned=False, last_accessed=None,
        formdata=None):
    return {
        "entries": [{"url": u, "title": t} for u, t in entries],
        "index": index if index is not None else len(entries),
        "pinned": pinned,
        "lastAccessed": last_accessed,
        **({"formdata": formdata} if formdata else {}),
    }
