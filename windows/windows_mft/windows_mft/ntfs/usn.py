r"""Parser for the NTFS change journal ``$Extend\$UsnJrnl:$J`` data stream.

USN_RECORD_V2 layout::

    0x00 u32  record length
    0x04 u16  major version (2)
    0x06 u16  minor version
    0x08 u64  file reference number      (entry | seq<<48)
    0x10 u64  parent file reference number
    0x18 u64  USN
    0x20 u64  timestamp (FILETIME, UTC)
    0x28 u32  reason flags
    0x2c u32  source info flags
    0x30 u32  security id
    0x34 u32  file attributes
    0x38 u16  file-name length (bytes)
    0x3a u16  file-name offset
    ....      file name (UTF-16LE)

The stream is sparse: long runs of NUL bytes between records are skipped.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

from windows_mft.ntfs.attributes import filetime_to_utc

REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}

_ATTR = {
    0x00000001: "READONLY", 0x00000002: "HIDDEN", 0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY", 0x00000020: "ARCHIVE", 0x00000040: "DEVICE",
    0x00000080: "NORMAL", 0x00000100: "TEMPORARY", 0x00000200: "SPARSE",
    0x00000400: "REPARSE_POINT", 0x00000800: "COMPRESSED", 0x00001000: "OFFLINE",
    0x00004000: "ENCRYPTED",
}


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

    def reason_names(self) -> list[str]:
        return [v for k, v in REASONS.items() if self.reason & k]

    def attribute_names(self) -> list[str]:
        return [v for k, v in _ATTR.items() if self.file_attributes & k]


def _decode_v2v3(buf: memoryview, off: int, length: int) -> UsnRecord | None:
    if length < 0x3c or off + length > len(buf):
        return None
    major = struct.unpack_from("<H", buf, off + 4)[0]
    if major == 2:
        fref, pref = struct.unpack_from("<QQ", buf, off + 8)
        base = off + 0x18
    elif major == 3:                       # 128-bit file ids
        fref = int.from_bytes(bytes(buf[off + 8:off + 16]), "little")
        pref = int.from_bytes(bytes(buf[off + 24:off + 32]), "little")
        base = off + 0x28
    else:
        return None
    usn = struct.unpack_from("<Q", buf, base)[0]
    ts = struct.unpack_from("<Q", buf, base + 8)[0]
    reason, source, sec_id, attrs = struct.unpack_from("<IIII", buf, base + 16)
    name_len = struct.unpack_from("<H", buf, base + 32)[0]
    name_off = struct.unpack_from("<H", buf, base + 34)[0]
    name = bytes(buf[off + name_off: off + name_off + name_len]) \
        .decode("utf-16-le", "replace")
    return UsnRecord(
        usn=usn, timestamp=filetime_to_utc(ts),
        file_entry=fref & 0x0000FFFFFFFFFFFF, file_sequence=fref >> 48,
        parent_entry=pref & 0x0000FFFFFFFFFFFF, parent_sequence=pref >> 48,
        reason=reason, source_info=source, file_attributes=attrs, name=name,
    )


def iter_usn(data: bytes) -> Iterator[UsnRecord]:
    buf = memoryview(data)
    n = len(buf)
    off = 0
    while off + 4 <= n:
        length = struct.unpack_from("<I", buf, off)[0]
        if length == 0:
            # sparse gap - jump to the next non-zero 8-byte aligned position
            nxt = off + 8
            while nxt + 4 <= n and buf[nxt:nxt + 4] == b"\x00\x00\x00\x00":
                nxt += 8
            if nxt <= off:
                break
            off = nxt
            continue
        if length < 0x3c or length > 0x10000 or off + length > n:
            off += 8
            continue
        rec = _decode_v2v3(buf, off, length)
        if rec is not None:
            yield rec
        off += (length + 7) & ~7
