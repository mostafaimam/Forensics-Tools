r"""USN_RECORD (v2 / v3) parsing, sequential and carving."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

REASONS = {
    0x00000001: "DATA_OVERWRITE", 0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION", 0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND", 0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE", 0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE", 0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME", 0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE", 0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE", 0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE", 0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE", 0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE", 0x00800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}

_ATTR = {
    0x0001: "READONLY", 0x0002: "HIDDEN", 0x0004: "SYSTEM",
    0x0010: "DIRECTORY", 0x0020: "ARCHIVE", 0x0100: "TEMPORARY",
    0x0200: "SPARSE", 0x0400: "REPARSE_POINT", 0x0800: "COMPRESSED",
    0x1000: "OFFLINE", 0x4000: "ENCRYPTED",
}

_SOURCE = {0x01: "DATA_MANAGEMENT", 0x02: "AUXILIARY_DATA",
           0x04: "REPLICATION_MANAGEMENT", 0x08: "CLIENT_REPLICATION_MGMT"}


def filetime_to_utc(ticks: int):
    if ticks <= 0:
        return None
    try:
        return _FT_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class UsnRecord:
    usn: int
    timestamp: datetime | None
    file_entry: int
    file_sequence: int
    parent_entry: int
    parent_sequence: int
    reason: int
    source_info: int
    file_attributes: int
    name: str
    offset: int = 0
    carved: bool = False

    def reason_names(self) -> list[str]:
        return [v for k, v in REASONS.items() if self.reason & k]

    def attribute_names(self) -> list[str]:
        return [v for k, v in _ATTR.items() if self.file_attributes & k]

    def source_names(self) -> list[str]:
        return [v for k, v in _SOURCE.items() if self.source_info & k]

    def iso(self) -> str:
        return self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ") \
            if self.timestamp else ""


def _decode(buf: memoryview, off: int, length: int) -> UsnRecord | None:
    if length < 0x3C or off + length > len(buf):
        return None
    major = struct.unpack_from("<H", buf, off + 4)[0]
    if major == 2:
        fref, pref = struct.unpack_from("<QQ", buf, off + 8)
        base = off + 0x18
        fe, fs = fref & 0xFFFFFFFFFFFF, fref >> 48
        pe, ps = pref & 0xFFFFFFFFFFFF, pref >> 48
    elif major == 3:
        fref = int.from_bytes(bytes(buf[off + 8:off + 24]), "little")
        pref = int.from_bytes(bytes(buf[off + 24:off + 40]), "little")
        base = off + 0x28
        fe, fs = fref & 0xFFFFFFFFFFFF, (fref >> 48) & 0xFFFF
        pe, ps = pref & 0xFFFFFFFFFFFF, (pref >> 48) & 0xFFFF
    else:
        return None
    try:
        usn = struct.unpack_from("<Q", buf, base)[0]
        ts = struct.unpack_from("<Q", buf, base + 8)[0]
        reason, source, _sec, attrs = struct.unpack_from("<IIII", buf,
                                                         base + 16)
        name_len = struct.unpack_from("<H", buf, base + 32)[0]
        name_off = struct.unpack_from("<H", buf, base + 34)[0]
    except struct.error:
        return None
    if name_len == 0 or name_len > 512 or name_off < 0x3C \
            or off + name_off + name_len > len(buf):
        return None
    name = bytes(buf[off + name_off:off + name_off + name_len]) \
        .decode("utf-16-le", "replace")
    if not name or any(ord(c) < 32 for c in name):
        return None
    ft = filetime_to_utc(ts)
    if ft and not (2000 <= ft.year <= 2100):
        return None
    return UsnRecord(usn=usn, timestamp=ft, file_entry=fe, file_sequence=fs,
                     parent_entry=pe, parent_sequence=ps, reason=reason,
                     source_info=source, file_attributes=attrs, name=name,
                     offset=off)


def iter_sequential(data: bytes) -> Iterator[UsnRecord]:
    """Walk a $J stream in order, skipping the leading sparse region."""
    buf = memoryview(data)
    n = len(buf)
    off = 0
    while off + 4 <= n:
        length = struct.unpack_from("<I", buf, off)[0]
        if length == 0:
            nxt = off + 8
            while nxt + 8 <= n and buf[nxt:nxt + 8] == b"\x00" * 8:
                nxt += 8
            if nxt <= off:
                break
            off = nxt
            continue
        if length < 0x3C or length > 0x10000 or off + length > n:
            off += 8
            continue
        rec = _decode(buf, off, length)
        if rec is not None:
            yield rec
        off += (length + 7) & ~7


def iter_carved(data: bytes) -> Iterator[UsnRecord]:
    """Scan every 8-byte boundary for a plausible USN_RECORD (v2/v3).

    Used on unallocated space / slack: finds records the sequential walk
    would miss because the length field or a neighbour is corrupt.
    """
    buf = memoryview(data)
    n = len(buf)
    seen: set[tuple] = set()
    for off in range(0, n - 0x3C, 8):
        major = struct.unpack_from("<H", buf, off + 4)[0]
        if major not in (2, 3):
            continue
        length = struct.unpack_from("<I", buf, off)[0]
        if not (0x3C <= length <= 0x1000):
            # try a best-effort fixed guess
            length = min(0x3C + 520, n - off)
        rec = _decode(buf, off, length)
        if rec is None:
            continue
        key = (rec.usn, rec.file_entry, rec.reason, rec.name)
        if key in seen:
            continue
        seen.add(key)
        rec.carved = True
        yield rec
