"""ESE column type constants + value decoding."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

NIL = 0
BIT = 1
UNSIGNED_BYTE = 2
SHORT = 3
LONG = 4
CURRENCY = 5
IEEE_SINGLE = 6
IEEE_DOUBLE = 7
DATE_TIME = 8
BINARY = 9
TEXT = 10
LONG_BINARY = 11
LONG_TEXT = 12
SUPER_LONG_VALUE = 13
UNSIGNED_LONG = 14
LONG_LONG = 15
GUID = 16
UNSIGNED_SHORT = 17
UNSIGNED_LONG_LONG = 18

FIXED_SIZE = {
    BIT: 1, UNSIGNED_BYTE: 1, SHORT: 2, UNSIGNED_SHORT: 2,
    LONG: 4, UNSIGNED_LONG: 4, IEEE_SINGLE: 4,
    CURRENCY: 8, IEEE_DOUBLE: 8, DATE_TIME: 8, LONG_LONG: 8,
    UNSIGNED_LONG_LONG: 8, GUID: 16,
}

LONG_TYPES = {LONG_BINARY, LONG_TEXT, SUPER_LONG_VALUE}
TEXT_TYPES = {TEXT, LONG_TEXT}

_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)
_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ole_datetime(value: float) -> str:
    try:
        return (_OLE_EPOCH + timedelta(days=value)).strftime(
            "%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def filetime(ticks: int) -> str:
    if ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


def decode(coltype: int, raw: bytes, code_page: int = 1200):
    if raw is None:
        return None
    try:
        if coltype == BIT:
            return bool(raw[0] & 1) if raw else None
        if coltype == UNSIGNED_BYTE:
            return raw[0] if raw else None
        if coltype == SHORT:
            return struct.unpack("<h", raw[:2].ljust(2, b"\0"))[0]
        if coltype == UNSIGNED_SHORT:
            return struct.unpack("<H", raw[:2].ljust(2, b"\0"))[0]
        if coltype == LONG:
            return struct.unpack("<i", raw[:4].ljust(4, b"\0"))[0]
        if coltype == UNSIGNED_LONG:
            return struct.unpack("<I", raw[:4].ljust(4, b"\0"))[0]
        if coltype == LONG_LONG or coltype == CURRENCY:
            return struct.unpack("<q", raw[:8].ljust(8, b"\0"))[0]
        if coltype == UNSIGNED_LONG_LONG:
            return struct.unpack("<Q", raw[:8].ljust(8, b"\0"))[0]
        if coltype == IEEE_SINGLE:
            return struct.unpack("<f", raw[:4].ljust(4, b"\0"))[0]
        if coltype == IEEE_DOUBLE:
            return struct.unpack("<d", raw[:8].ljust(8, b"\0"))[0]
        if coltype == DATE_TIME:
            val = struct.unpack("<d", raw[:8].ljust(8, b"\0"))[0]
            return ole_datetime(val)
        if coltype == GUID:
            import uuid
            return str(uuid.UUID(bytes_le=raw[:16]))
        if coltype in TEXT_TYPES:
            enc = "utf-16-le" if code_page in (1200, 0) else "cp1252"
            if code_page == 1252:
                enc = "cp1252"
            return raw.decode(enc, "replace").rstrip("\x00")
        # BINARY / LONG_BINARY / everything else
        return raw
    except (struct.error, ValueError, IndexError):
        return raw
