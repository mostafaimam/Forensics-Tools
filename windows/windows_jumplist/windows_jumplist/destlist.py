r"""Parse the ``DestList`` stream of an ``automaticDestinations-ms`` jump list.

Header (32 bytes)::

    0x00  u32  format version   1 = Windows 7 · 3/4 = Windows 10
    0x04  u32  number of entries
    0x08  u32  number of pinned entries
    0x10  u32  last entry number
    0x18  u32  last revision number

Each entry maps a numbered LNK stream to its MRU position, the target path,
the last time that target was opened *through this application*, the NetBIOS
name of the machine, and the pin state.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class DestListEntry:
    entry_number: int             # matches the OLE stream name
    mru_position: int             # 0 = most recently used
    path: str
    last_used: datetime | None
    hostname: str
    pinned: bool
    new_volume_id: str = ""
    new_object_id: str = ""
    birth_object_id: str = ""
    interaction_count: int = 0


@dataclass
class DestList:
    version: int
    entry_count: int
    pinned_count: int
    last_entry_number: int
    entries: list


def parse(data: bytes) -> DestList:
    if len(data) < 32:
        raise ValueError("DestList stream too small")
    version, count, pinned = struct.unpack_from("<III", data, 0)
    last_entry = struct.unpack_from("<I", data, 0x10)[0]

    entries: list[DestListEntry] = []
    pos = 32
    mru = 0
    n = len(data)
    while pos + 4 <= n and len(entries) < max(count, 1) * 4 + 16:
        try:
            if version >= 3:
                entry, consumed = _entry_v3(data, pos, mru, version)
            else:
                entry, consumed = _entry_v1(data, pos, mru)
        except (struct.error, ValueError):
            break
        if consumed <= 0:
            break
        entries.append(entry)
        mru += 1
        pos += consumed
        if len(entries) >= count and count:
            break
    return DestList(version, count, pinned, last_entry, entries)


def _guid(b: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=b)).upper()
    except (ValueError, IndexError):
        return ""


def _entry_v3(data: bytes, pos: int, mru: int, version: int = 4):
    # 0x00 checksum(8) · NewVolumeID(16) · NewObjectID(16) ·
    # BirthVolumeID(16) · BirthObjectID(16) · NetBIOSName(16)
    # 0x58 u32 entry number · 0x5c u32 · 0x60 f32 · 0x64 u64 FILETIME
    # 0x6c i32 pin (-1 = unpinned) · 0x70 u32 · 0x74 u32 access count
    # 0x78 u32 · 0x7c u32 · 0x80 u16 path char count · 0x82 path (UTF-16LE)
    # then u32  (format version 4 only)
    new_vol = _guid(data[pos + 0x08:pos + 0x18])
    new_obj = _guid(data[pos + 0x18:pos + 0x28])
    birth_obj = _guid(data[pos + 0x38:pos + 0x48])
    hostname = data[pos + 0x48:pos + 0x58].split(b"\x00")[0].decode(
        "latin-1", "replace")
    entry_number = struct.unpack_from("<I", data, pos + 0x58)[0]
    ft = struct.unpack_from("<Q", data, pos + 0x64)[0]
    pin_raw = struct.unpack_from("<i", data, pos + 0x6C)[0]
    access_count = struct.unpack_from("<I", data, pos + 0x74)[0]
    path_len = struct.unpack_from("<H", data, pos + 0x80)[0]
    path_start = pos + 0x82
    path = data[path_start:path_start + path_len * 2].decode("utf-16-le", "replace")
    consumed = 0x82 + path_len * 2 + (4 if version >= 4 else 0)
    return DestListEntry(
        entry_number=entry_number, mru_position=mru, path=path,
        last_used=_ft(ft), hostname=hostname, pinned=pin_raw >= 0,
        new_volume_id=new_vol, new_object_id=new_obj, birth_object_id=birth_obj,
        interaction_count=access_count,
    ), consumed


def _entry_v1(data: bytes, pos: int, mru: int):
    # Windows 7: 0x00 checksum(8) · NewVolumeID(16) · NewObjectID(16)
    # BirthVolumeID(16) · BirthObjectID(16) · NetBIOSName(16) · entry#(4)
    # unk(4) · float(4) · FILETIME(8) · entry#2(4) · path len(2) · path
    new_vol = _guid(data[pos + 0x08:pos + 0x18])
    new_obj = _guid(data[pos + 0x18:pos + 0x28])
    birth_obj = _guid(data[pos + 0x38:pos + 0x48])
    hostname = data[pos + 0x48:pos + 0x58].split(b"\x00")[0].decode(
        "latin-1", "replace")
    entry_number = struct.unpack_from("<I", data, pos + 0x58)[0]
    ft = struct.unpack_from("<Q", data, pos + 0x64)[0]
    path_len = struct.unpack_from("<H", data, pos + 0x70)[0]
    path_start = pos + 0x72
    path = data[path_start:path_start + path_len * 2].decode("utf-16-le", "replace")
    consumed = 0x72 + path_len * 2
    return DestListEntry(
        entry_number=entry_number, mru_position=mru, path=path,
        last_used=_ft(ft), hostname=hostname, pinned=False,
        new_volume_id=new_vol, new_object_id=new_obj, birth_object_id=birth_obj,
    ), consumed
