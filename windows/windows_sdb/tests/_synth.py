"""Hand-build a minimal .sdb with a dangerous InjectDll shim + a patch."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

MAGIC = 0x66626473
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(dt):
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


class _StrTab:
    def __init__(self):
        self.items: list[str] = []
        self.offs: dict[str, int] = {}
        self._cursor = 0

    def ref(self, s: str) -> int:
        if s not in self.offs:
            self.offs[s] = self._cursor
            self.items.append(s)
            body = s.encode("utf-16-le") + b"\x00\x00"
            self._cursor += 2 + 4 + len(body)
        return self.offs[s]

    def payload(self) -> bytes:
        out = bytearray()
        for s in self.items:
            body = s.encode("utf-16-le") + b"\x00\x00"
            out += struct.pack("<HI", 0x8801, len(body)) + body
        return bytes(out)


def _null(tag):
    return struct.pack("<H", tag)


def _dword(tag, v):
    return struct.pack("<HI", tag, v)


def _qword(tag, v):
    return struct.pack("<HQ", tag, v)


def _strref(tag, ref):
    return struct.pack("<HI", tag, ref)


def _bin(tag, data):
    return struct.pack("<HI", tag, len(data)) + data


def _list(tag, *children):
    body = b"".join(children)
    return struct.pack("<HI", tag, len(body)) + body


def build_sdb() -> bytes:
    st = _StrTab()
    r = st.ref
    guid_db = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444").bytes_le
    guid_exe = uuid.UUID("bbbbbbbb-5555-6666-7777-888888888888").bytes_le
    when = _ft(datetime(2026, 3, 16, 9, 0, 0, tzinfo=timezone.utc))

    shim = _list(
        0x7004,
        _strref(0x6001, r("InjectDll")),
        _strref(0x6009, r("C:\\Users\\victim\\AppData\\Local\\evil.dll")),
        _strref(0x6002, r("compatibility helper")),
    )
    patch = _list(
        0x7005,
        _strref(0x6001, r("EvilPatch")),
        _bin(0x9002, bytes(range(64))),
    )
    library = _list(0x7002, shim, patch)

    exe = _list(
        0x7007,
        _strref(0x6001, r("svchost.exe")),
        _strref(0x6006, r("Generic Host Process")),
        _strref(0x6005, r("Acme Corp")),
        _bin(0x9004, guid_exe),
        _list(0x7008, _strref(0x6001, r("svchost.exe")),
              _strref(0x6008, r("Microsoft Corporation"))),
        _list(0x7009, _strref(0x6001, r("InjectDll"))),
        _list(0x700A, _strref(0x6001, r("EvilPatch"))),
    )

    database = _list(
        0x7001,
        _strref(0x6001, r("EvilShimDB")),
        _qword(0x5001, when),
        _bin(0x9007, guid_db),
        library,
        exe,
    )

    strtab = st.payload()
    stringtable = struct.pack("<HI", 0x7801, len(strtab)) + strtab

    header = struct.pack("<III", 2, 1, MAGIC)
    return header + database + stringtable


def build_benign_sdb() -> bytes:
    """A system-style DB with only an ordinary layer."""
    st = _StrTab()
    r = st.ref
    database = _list(
        0x7001,
        _strref(0x6001, r("sysmain.sdb")),
        _list(0x7002,
              _list(0x7004, _strref(0x6001, r("VirtualRegistry")),
                    _strref(0x6009, r("aclayers.dll")))),
    )
    strtab = st.payload()
    stringtable = struct.pack("<HI", 0x7801, len(strtab)) + strtab
    return struct.pack("<III", 2, 1, MAGIC) + database + stringtable
