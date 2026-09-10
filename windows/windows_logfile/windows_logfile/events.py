"""Reconstruct high-level file-system events from log records."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}

_CREATE_OPS = {0x0C, 0x0E}          # AddIndexEntryRoot / Allocation
_DELETE_OPS = {0x0D, 0x0F}          # DeleteIndexEntryRoot / Allocation
_RENAME_OPS = {0x13, 0x14}          # UpdateFileNameRoot / Allocation
_MFT_INIT = 0x02                    # InitializeFileRecordSegment
_MFT_FREE = 0x03                    # DeallocateFileRecordSegment


def _ft(v: int) -> str:
    if not v or v > 0x7FFF_FFFF_FFFF_FFFF:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


@dataclass
class FileName:
    name: str = ""
    namespace: str = ""
    parent_mft: int = 0
    parent_seq: int = 0
    created: str = ""
    modified: str = ""
    mft_modified: str = ""
    accessed: str = ""
    alloc_size: int = 0
    real_size: int = 0
    flags: int = 0


def parse_filename_attr(buf: bytes, off: int = 0) -> FileName | None:
    if len(buf) - off < 0x42:
        return None
    fn = FileName()
    ref = struct.unpack_from("<Q", buf, off)[0]
    fn.parent_mft = ref & ((1 << 48) - 1)
    fn.parent_seq = ref >> 48
    (c, m, mm, a, alloc, real, flags) = struct.unpack_from(
        "<QQQQQQI", buf, off + 8)
    fn.created, fn.modified, fn.mft_modified, fn.accessed = (
        _ft(c), _ft(m), _ft(mm), _ft(a))
    fn.alloc_size, fn.real_size, fn.flags = alloc, real, flags
    nlen = buf[off + 0x40]
    ns = buf[off + 0x41]
    fn.namespace = _NAMESPACE.get(ns, str(ns))
    name = buf[off + 0x42: off + 0x42 + nlen * 2]
    fn.name = name.decode("utf-16-le", "replace")
    return fn


def _score(buf: bytes, off: int) -> tuple[int, FileName | None]:
    """Higher score = more likely this offset holds a real FILE_NAME."""
    if len(buf) - off < 0x42:
        return -1, None
    nlen = buf[off + 0x40]
    ns = buf[off + 0x41]
    want = off + 0x42 + nlen * 2
    fn = parse_filename_attr(buf, off)
    if fn is None:
        return -1, None
    s = 0
    if ns <= 3:
        s += 2
    if 1 <= nlen <= 255 and want <= len(buf) <= want + 8:
        s += 4
    elif want <= len(buf):
        s += 1
    if fn.name and fn.name.isprintable() and "\x00" not in fn.name \
            and "/" not in fn.name:
        s += 2
    if fn.created and fn.modified:
        s += 1
    return s, fn


def _filename_from_index_entry(buf: bytes) -> FileName | None:
    """The redo data may be a full index entry (FILE_NAME at 0x10) or the
    FILE_NAME attribute on its own (at 0x00).  Pick the better fit."""
    s0, f0 = _score(buf, 0)
    s16, f16 = _score(buf, 0x10)
    if s16 > s0 and f16 is not None:
        try:
            ref = struct.unpack_from("<Q", buf, 0)[0]
            f16._mft = ref & ((1 << 48) - 1)   # type: ignore[attr-defined]
        except struct.error:
            pass
        return f16
    return f0 if f0 is not None else f16


@dataclass
class Event:
    lsn: int
    action: str
    name: str = ""
    path_hint: str = ""
    mft: int = 0
    parent_mft: int = 0
    namespace: str = ""
    created: str = ""
    modified: str = ""
    real_size: int = 0
    redo_op: str = ""
    undo_op: str = ""
    transaction_id: int = 0
    page: int = 0
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "lsn": self.lsn, "action": self.action, "name": self.name,
            "mft": self.mft, "parent_mft": self.parent_mft,
            "namespace": self.namespace, "created": self.created,
            "modified": self.modified, "real_size": self.real_size,
            "redo_op": self.redo_op, "undo_op": self.undo_op,
            "transaction_id": self.transaction_id, "page": self.page,
            "source": self.source, "notable": ";".join(self.notable),
        }


def reconstruct(records, source: str) -> list[Event]:
    out: list[Event] = []
    for r in records:
        op = r.redo_op
        action = None
        fn = None
        if op in _CREATE_OPS:
            action = "file created (index entry added)"
            fn = _filename_from_index_entry(r.redo)
        elif op in _DELETE_OPS:
            action = "file deleted (index entry removed)"
            fn = _filename_from_index_entry(r.redo) or \
                _filename_from_index_entry(r.undo)
        elif op in _RENAME_OPS:
            action = "file name / timestamps updated"
            fn = _filename_from_index_entry(r.redo)
        elif op == _MFT_INIT:
            action = "MFT record initialised"
        elif op == _MFT_FREE:
            action = "MFT record freed"
        elif op == 0x07:
            action = "resident attribute value updated"
        elif op == 0x08:
            action = "non-resident data written"
        else:
            continue

        ev = Event(lsn=r.lsn, action=action, redo_op=r.redo_name,
                   undo_op=r.undo_name, transaction_id=r.transaction_id,
                   page=r.page, source=source)
        if fn and fn.name:
            ev.name = fn.name
            ev.parent_mft = fn.parent_mft
            ev.namespace = fn.namespace
            ev.created = fn.created
            ev.modified = fn.modified
            ev.real_size = fn.real_size
            ev.mft = getattr(fn, "_mft", 0)
        out.append(ev)
    return out
