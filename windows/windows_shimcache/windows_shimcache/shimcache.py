r"""Parse the ``AppCompatCache`` (a.k.a. ShimCache) binary value.

The value lives at ``<ControlSet>\Control\Session Manager\AppCompatCache``
in the ``SYSTEM`` hive.  It records executables the Application Compatibility
subsystem has *seen* - strong evidence of presence, and (Windows 7 and later,
with a caveat) of execution order.  Every entry carries the target's
``$STANDARD_INFORMATION`` last-modified time, not an execution time.

Formats, detected by the first bytes:

* Windows 10 / 11  - header length ``0x30`` / ``0x34``; ``10ts`` entry magic
* Windows 8 / 8.1  - ``00ts`` / ``10ts`` entry magic, header ``0x80``
* Windows 7 / 2008R2 - magic ``0xBADC0FEE``, entries at offset ``0x80``
* Windows XP / 2003 - magic ``0xDEADBEEF``, 0x190-byte entries at ``0x190``
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

WIN10 = "windows-10"
WIN8 = "windows-8"
WIN7 = "windows-7"
WINXP = "windows-xp"


class ShimCacheError(ValueError):
    pass


def _ft(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class ShimEntry:
    position: int                 # 0 = most recently added
    path: str
    last_modified: datetime | None
    executed: bool | None = None  # only meaningful on Windows 7/8
    data_size: int = 0
    control_set: str = ""

    @property
    def last_modified_iso(self) -> str:
        d = self.last_modified
        return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if d else ""


def detect_format(blob: bytes) -> str:
    if len(blob) < 8:
        raise ShimCacheError("value too small")
    sig = struct.unpack_from("<I", blob, 0)[0]
    if sig == 0xDEADBEEF:
        return WINXP
    if sig == 0xBADC0FEE:
        return WIN7
    if sig in (0x00000080, 0x00000034, 0x00000030):
        # 0x80 = Win8, 0x30/0x34 = Win10; disambiguate by the entry magic
        header_len = sig
        magic = blob[header_len:header_len + 4]
        if magic in (b"10ts", b"00ts"):
            return WIN10 if header_len in (0x30, 0x34) else WIN8
        return WIN10 if header_len in (0x30, 0x34) else WIN8
    # some Win10 builds start with 0x34 followed immediately by "10ts"
    if blob[0x34:0x38] == b"10ts" or blob[0x30:0x34] == b"10ts":
        return WIN10
    raise ShimCacheError(f"unrecognised AppCompatCache signature {sig:#010x}")


def parse(blob: bytes, control_set: str = "") -> list[ShimEntry]:
    fmt = detect_format(blob)
    if fmt == WIN10:
        return _parse_win10(blob, control_set)
    if fmt == WIN8:
        return _parse_win8(blob, control_set)
    if fmt == WIN7:
        return _parse_win7(blob, control_set)
    return _parse_winxp(blob, control_set)


# -- Windows 10 / 11 --------------------------------------------------------
def _parse_win10(blob: bytes, cs: str) -> list[ShimEntry]:
    header_len = struct.unpack_from("<I", blob, 0)[0]
    if header_len not in (0x30, 0x34):
        header_len = 0x30 if blob[0x30:0x34] == b"10ts" else 0x34
    pos = header_len
    n = len(blob)
    out: list[ShimEntry] = []
    idx = 0
    while pos + 12 <= n:
        if blob[pos:pos + 4] != b"10ts":
            break
        entry_size = struct.unpack_from("<I", blob, pos + 8)[0]
        body = pos + 12
        if entry_size < 2 or body + entry_size > n:
            break
        path_len = struct.unpack_from("<H", blob, body)[0]
        p = body + 2
        path = blob[p:p + path_len].decode("utf-16-le", "replace")
        p += path_len
        ft = struct.unpack_from("<Q", blob, p)[0] if p + 8 <= n else 0
        p += 8
        data_size = struct.unpack_from("<I", blob, p)[0] if p + 4 <= n else 0
        out.append(ShimEntry(idx, path, _ft(ft), None, data_size, cs))
        idx += 1
        pos = body + entry_size
    return out


# -- Windows 8 / 8.1 ------------------------------------------------------
def _parse_win8(blob: bytes, cs: str) -> list[ShimEntry]:
    pos = 0x80
    n = len(blob)
    out: list[ShimEntry] = []
    idx = 0
    while pos + 12 <= n:
        magic = blob[pos:pos + 4]
        if magic not in (b"00ts", b"10ts"):
            break
        entry_size = struct.unpack_from("<I", blob, pos + 8)[0]
        body = pos + 12
        if body + entry_size > n:
            break
        path_len = struct.unpack_from("<H", blob, body)[0]
        path = blob[body + 2:body + 2 + path_len].decode("utf-16-le", "replace")
        q = body + 2 + path_len
        # package id (u16 len + string) then flags(u32) unknown(u32) then FILETIME
        pkg_len = struct.unpack_from("<H", blob, q)[0]
        q += 2 + pkg_len
        q += 8                                    # flags + unknown
        ft = struct.unpack_from("<Q", blob, q)[0] if q + 8 <= n else 0
        out.append(ShimEntry(idx, path, _ft(ft), None, 0, cs))
        idx += 1
        pos = body + entry_size
    return out


# -- Windows 7 / 2008 R2 -----------------------------------------------
def _parse_win7(blob: bytes, cs: str) -> list[ShimEntry]:
    num_entries = struct.unpack_from("<I", blob, 4)[0]
    is_64 = _win7_is_64bit(blob)
    entry_size = 48 if is_64 else 32
    base = 0x80
    n = len(blob)
    out: list[ShimEntry] = []
    for i in range(num_entries):
        e = base + i * entry_size
        if e + entry_size > n:
            break
        path_len, _path_max = struct.unpack_from("<HH", blob, e)
        if is_64:
            path_off = struct.unpack_from("<Q", blob, e + 8)[0]
            ft = struct.unpack_from("<Q", blob, e + 16)[0]
            shim_flags = struct.unpack_from("<I", blob, e + 24)[0]
            data_size = struct.unpack_from("<Q", blob, e + 32)[0]
        else:
            path_off = struct.unpack_from("<I", blob, e + 4)[0]
            ft = struct.unpack_from("<Q", blob, e + 8)[0]
            shim_flags = struct.unpack_from("<I", blob, e + 16)[0]
            data_size = struct.unpack_from("<I", blob, e + 20)[0]
        path = ""
        if 0 < path_len and path_off + path_len <= n:
            path = blob[path_off:path_off + path_len].decode("utf-16-le", "replace")
        executed = bool(shim_flags & 0x2)
        out.append(ShimEntry(i, path, _ft(ft), executed, data_size, cs))
    return out


def _win7_is_64bit(blob: bytes) -> bool:
    # heuristic: on 64-bit the first entry's path offset is > 0x80 + n*48
    num = struct.unpack_from("<I", blob, 4)[0] or 1
    try:
        off32 = struct.unpack_from("<I", blob, 0x80 + 4)[0]
        off64 = struct.unpack_from("<Q", blob, 0x80 + 8)[0]
    except struct.error:
        return True
    end32 = 0x80 + num * 32
    end64 = 0x80 + num * 48
    if off64 == end64 or (end64 <= off64 < len(blob)):
        return True
    if off32 == end32 or (end32 <= off32 < len(blob)):
        return False
    return len(blob) > 0x80 + num * 40


# -- Windows XP / 2003 ------------------------------------------------
def _parse_winxp(blob: bytes, cs: str) -> list[ShimEntry]:
    num_entries = struct.unpack_from("<I", blob, 4)[0]
    base = 0x190
    entry_size = 0x228
    n = len(blob)
    out: list[ShimEntry] = []
    for i in range(num_entries):
        e = base + i * entry_size
        if e + entry_size > n:
            break
        path = blob[e:e + 528].split(b"\x00\x00")[0].decode("utf-16-le", "replace")
        ft = struct.unpack_from("<Q", blob, e + 528)[0]
        data_size = struct.unpack_from("<Q", blob, e + 536)[0]
        out.append(ShimEntry(i, path, _ft(ft), None, data_size, cs))
    return out
