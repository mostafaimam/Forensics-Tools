"""Decode registry value data by REG_* type."""

from __future__ import annotations

import struct

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11

TYPE_NAMES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
}


def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"0x{t:08X}")


def _wstr(b: bytes) -> str:
    return b.decode("utf-16-le", "replace").split("\x00")[0]


def decode(data_type: int, raw: bytes):
    """Return a Python value (str / int / list[str] / bytes)."""
    try:
        if data_type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
            return _wstr(raw)
        if data_type == REG_MULTI_SZ:
            s = raw.decode("utf-16-le", "replace")
            return [p for p in s.split("\x00") if p]
        if data_type == REG_DWORD:
            return struct.unpack_from("<I", raw, 0)[0] if len(raw) >= 4 else 0
        if data_type == REG_DWORD_BIG_ENDIAN:
            return struct.unpack_from(">I", raw, 0)[0] if len(raw) >= 4 else 0
        if data_type == REG_QWORD:
            return struct.unpack_from("<Q", raw, 0)[0] if len(raw) >= 8 else 0
    except struct.error:
        pass
    return raw


def to_text(value) -> str:
    if isinstance(value, list):
        return " | ".join(value)
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    return str(value)
