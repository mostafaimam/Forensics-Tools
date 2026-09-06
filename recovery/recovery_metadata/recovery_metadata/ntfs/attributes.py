"""Decode the $STANDARD_INFORMATION and $FILE_NAME attribute bodies."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

NS_POSIX = 0
NS_WIN32 = 1
NS_DOS = 2
NS_WIN32_DOS = 3


def iso_utc(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def filetime_to_utc(ticks: int) -> datetime | None:
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class StandardInformation:
    created: datetime | None
    modified: datetime | None
    mft_modified: datetime | None
    accessed: datetime | None


@dataclass
class FileName:
    parent_entry: int
    parent_sequence: int
    created: datetime | None
    modified: datetime | None
    mft_modified: datetime | None
    accessed: datetime | None
    logical_size: int
    allocated_size: int
    flags: int
    namespace: int
    name: str


def parse_standard_information(body: bytes) -> StandardInformation | None:
    if len(body) < 32:
        return None
    c, m, r, a = struct.unpack_from("<QQQQ", body, 0)
    return StandardInformation(
        filetime_to_utc(c), filetime_to_utc(m),
        filetime_to_utc(r), filetime_to_utc(a),
    )


def parse_file_name(body: bytes) -> FileName | None:
    if len(body) < 66:
        return None
    parent = struct.unpack_from("<Q", body, 0)[0]
    parent_entry = parent & 0x0000FFFFFFFFFFFF
    parent_seq = parent >> 48
    c, m, r, a = struct.unpack_from("<QQQQ", body, 8)
    alloc, real = struct.unpack_from("<QQ", body, 40)
    flags = struct.unpack_from("<I", body, 56)[0]
    name_len = body[64]
    namespace = body[65]
    name = body[66:66 + name_len * 2].decode("utf-16-le", "replace")
    return FileName(
        parent_entry=parent_entry, parent_sequence=parent_seq,
        created=filetime_to_utc(c), modified=filetime_to_utc(m),
        mft_modified=filetime_to_utc(r), accessed=filetime_to_utc(a),
        logical_size=real, allocated_size=alloc, flags=flags,
        namespace=namespace, name=name,
    )


def best_file_name(names: list[FileName]) -> FileName | None:
    """Prefer a Win32 / Win32+DOS name over a pure DOS 8.3 or POSIX name."""
    if not names:
        return None
    for pref in (NS_WIN32_DOS, NS_WIN32, NS_POSIX, NS_DOS):
        for fn in names:
            if fn.namespace == pref:
                return fn
    return names[0]
