"""Binary reader for a single systemd journal file.

Reference: the on-disk format documented at
``https://systemd.io/JOURNAL_FILE_FORMAT/``.  We do not need the hash
tables: entries are found by walking the object arena linearly, which is
also the most corruption-tolerant strategy.
"""

from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

SIGNATURE = b"LPKSHHRH"

# incompatible header flags
INCOMPAT_COMPRESSED_XZ = 1 << 0
INCOMPAT_COMPRESSED_LZ4 = 1 << 1
INCOMPAT_KEYED_HASH = 1 << 2
INCOMPAT_COMPRESSED_ZSTD = 1 << 3
INCOMPAT_COMPACT = 1 << 4

# object types
OBJ_DATA = 1
OBJ_FIELD = 2
OBJ_ENTRY = 3
OBJ_DATA_HASH_TABLE = 4
OBJ_FIELD_HASH_TABLE = 5
OBJ_ENTRY_ARRAY = 6
OBJ_TAG = 7

# per-object compression flags
OBJ_COMPRESSED_XZ = 1 << 0
OBJ_COMPRESSED_LZ4 = 1 << 1
OBJ_COMPRESSED_ZSTD = 1 << 2

_ALIGN = 8


class JournalError(Exception):
    pass


@dataclass
class Entry:
    realtime_us: int
    monotonic_us: int
    boot_id: str
    seqnum: int
    fields: dict[str, str]
    file: str = ""

    @property
    def iso(self) -> str:
        if not self.realtime_us:
            return ""
        try:
            return (datetime.fromtimestamp(self.realtime_us / 1_000_000,
                                           timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        except (ValueError, OverflowError, OSError):
            return ""


@dataclass
class Header:
    incompatible_flags: int = 0
    compatible_flags: int = 0
    header_size: int = 0
    arena_size: int = 0
    tail_object_offset: int = 0
    n_objects: int = 0
    n_entries: int = 0
    file_id: str = ""
    machine_id: str = ""
    boot_id: str = ""


@dataclass
class ParseResult:
    header: Header = field(default_factory=Header)
    entries: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    lz4_skipped: int = 0
    zstd_skipped: int = 0
    bad_objects: int = 0


def _uuid(b: bytes) -> str:
    if len(b) != 16 or b == b"\x00" * 16:
        return ""
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _decompress(payload: bytes, obj_flags: int, res: ParseResult) -> str | None:
    comp = obj_flags & 0x07
    if not comp:
        return payload.decode("utf-8", "replace")
    if comp & OBJ_COMPRESSED_XZ:
        try:
            return lzma.decompress(payload).decode("utf-8", "replace")
        except lzma.LZMAError:
            res.bad_objects += 1
            return None
    if comp & OBJ_COMPRESSED_LZ4:
        res.lz4_skipped += 1
        return None
    if comp & OBJ_COMPRESSED_ZSTD:
        res.zstd_skipped += 1
        return None
    return None


class JournalFile:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.buf = fh.read()
        self.header = self._read_header()

    # -- header ----------------------------------------------------------
    def _read_header(self) -> Header:
        b = self.buf
        if len(b) < 240 or b[:8] != SIGNATURE:
            raise JournalError("not a systemd journal file (bad signature)")
        h = Header()
        h.compatible_flags = struct.unpack_from("<I", b, 8)[0]
        h.incompatible_flags = struct.unpack_from("<I", b, 12)[0]
        # state u8 @16, reserved 7
        h.file_id = _uuid(b[24:40])
        h.machine_id = _uuid(b[40:56])
        h.boot_id = _uuid(b[56:72])
        # seqnum_id @72..88
        (h.header_size, h.arena_size,
         _dhto, _dhts, _fhto, _fhts,
         h.tail_object_offset, h.n_objects, h.n_entries) = struct.unpack_from(
            "<9Q", b, 88)
        return h

    # -- object walk ---------------------------------------------------------
    def parse(self, res: ParseResult | None = None) -> ParseResult:
        res = res or ParseResult()
        res.header = self.header
        b = self.buf
        compact = bool(self.header.incompatible_flags & INCOMPAT_COMPACT)
        end = min(len(b), self.header.tail_object_offset
                  + 16 if self.header.tail_object_offset else len(b))
        off = self.header.header_size or 240
        seen = 0
        limit = max(self.header.n_objects * 4, 1_000_000)
        while off + 16 <= len(b) and seen < limit:
            seen += 1
            otype = b[off]
            oflags = b[off + 1]
            (osize,) = struct.unpack_from("<Q", b, off + 8)
            if osize < 16 or off + osize > len(b):
                res.bad_objects += 1
                break
            if otype == OBJ_ENTRY:
                e = self._entry(off, osize, oflags, compact, res)
                if e is not None:
                    res.entries.append(e)
            nxt = off + ((osize + _ALIGN - 1) & ~(_ALIGN - 1))
            if nxt <= off:
                break
            off = nxt
            if end and off >= end and otype != 0:
                # walked past the tail object; stop
                if off >= len(b):
                    break
        return res

    # -- one ENTRY object --------------------------------------------------
    def _entry(self, off: int, osize: int, oflags: int, compact: bool,
               res: ParseResult) -> Entry | None:
        b = self.buf
        try:
            seqnum, realtime, monotonic = struct.unpack_from("<QQQ", b, off + 16)
            boot_id = _uuid(b[off + 40:off + 56])
        except struct.error:
            res.bad_objects += 1
            return None
        items_off = off + 64
        item_size = 4 if compact else 16
        n_items = (osize - 64) // item_size
        fields: dict[str, str] = {}
        for i in range(n_items):
            p = items_off + i * item_size
            if p + item_size > off + osize:
                break
            if compact:
                (data_off,) = struct.unpack_from("<I", b, p)
            else:
                (data_off,) = struct.unpack_from("<Q", b, p)
            kv = self._data_payload(data_off, compact, res)
            if kv is None:
                continue
            k, _, v = kv.partition("=")
            if k:
                fields[k] = v
        return Entry(realtime_us=realtime, monotonic_us=monotonic,
                     boot_id=boot_id, seqnum=seqnum, fields=fields,
                     file=self.path)

    # -- one DATA object payload ------------------------------------------
    def _data_payload(self, data_off: int, compact: bool,
                      res: ParseResult) -> str | None:
        b = self.buf
        if data_off < 16 or data_off + 16 > len(b):
            return None
        if b[data_off] != OBJ_DATA:
            return None
        oflags = b[data_off + 1]
        (osize,) = struct.unpack_from("<Q", b, data_off + 8)
        if osize < 48 or data_off + osize > len(b):
            return None
        # DataObject: hash,next_hash,next_field,entry_offset,entry_array,
        # n_entries  = 6 * u64 ; + (compact) 2 * u32
        payload_start = data_off + 16 + 48
        if compact:
            payload_start += 8
        payload = b[payload_start:data_off + osize]
        if not payload:
            return None
        return _decompress(payload, oflags, res)


def read(path: str, res: ParseResult | None = None) -> ParseResult:
    jf = JournalFile(path)
    return jf.parse(res)
