"""Build a synthetic NTFS $LogFile (RSTR + RCRD pages, log records)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

PAGE = 4096
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt: datetime) -> int:
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


def _filename_attr(name, parent, *, created, modified, real=0,
                   namespace=1) -> bytes:
    b = bytearray(0x42 + len(name) * 2)
    struct.pack_into("<Q", b, 0x00, parent | (1 << 48))
    struct.pack_into("<Q", b, 0x08, ft(created))
    struct.pack_into("<Q", b, 0x10, ft(modified))
    struct.pack_into("<Q", b, 0x18, ft(modified))
    struct.pack_into("<Q", b, 0x20, ft(modified))
    struct.pack_into("<Q", b, 0x28, (real + 4095) & ~4095)
    struct.pack_into("<Q", b, 0x30, real)
    struct.pack_into("<I", b, 0x38, 0x20)
    b[0x40] = len(name)
    b[0x41] = namespace
    b[0x42:] = name.encode("utf-16-le")
    return bytes(b)


def _index_entry(mft, name, parent, **kw) -> bytes:
    fn = _filename_attr(name, parent, **kw)
    head = bytearray(0x10)
    struct.pack_into("<Q", head, 0, mft | (2 << 48))
    struct.pack_into("<H", head, 8, 0x10 + len(fn))
    struct.pack_into("<H", head, 0xA, len(fn))
    return bytes(head) + fn


def _op_record(redo_op, undo_op, redo=b"", undo=b"") -> bytes:
    hdr = bytearray(0x30)
    struct.pack_into("<HH", hdr, 0, redo_op, undo_op)
    ro = 0x30
    uo = 0x30 + len(redo)
    struct.pack_into("<HHHH", hdr, 4, ro, len(redo), uo, len(undo))
    return bytes(hdr) + redo + undo


def _log_record(lsn, redo_op, undo_op, *, redo=b"", undo=b"", tx=1) -> bytes:
    cd = _op_record(redo_op, undo_op, redo, undo)
    hdr = bytearray(0x30)
    struct.pack_into("<Q", hdr, 0x00, lsn)
    struct.pack_into("<Q", hdr, 0x08, lsn - 1 if lsn else 0)
    struct.pack_into("<Q", hdr, 0x10, 0)
    struct.pack_into("<I", hdr, 0x18, len(cd))
    struct.pack_into("<I", hdr, 0x20, 1)          # record type
    struct.pack_into("<I", hdr, 0x24, tx)
    return bytes(hdr) + cd


def _rcrd_page(records: list[bytes], seq=0xBEEF) -> bytes:
    page = bytearray(PAGE)
    page[0:4] = b"RCRD"
    usa_off, usa_cnt = 0x2A, 9
    struct.pack_into("<HH", page, 4, usa_off, usa_cnt)
    pos = 0x40
    for r in records:
        page[pos:pos + len(r)] = r
        pos += 0x30 + ((len(r) - 0x30 + 7) & ~7)
    # build USA: save block-end bytes, stamp the sequence
    seqb = struct.pack("<H", seq)
    fixups = []
    for i in range(1, usa_cnt):
        p = i * 512 - 2
        fixups.append(bytes(page[p:p + 2]))
        page[p:p + 2] = seqb
    page[usa_off:usa_off + 2] = seqb
    for i, fx in enumerate(fixups):
        page[usa_off + 2 + i * 2: usa_off + 4 + i * 2] = fx
    return bytes(page)


def _rstr_page() -> bytes:
    page = bytearray(PAGE)
    page[0:4] = b"RSTR"
    struct.pack_into("<HH", page, 4, 0x1E, 9)
    return bytes(page)


def build_logfile() -> bytes:
    c_early = datetime(2026, 3, 16, 8, 0, tzinfo=timezone.utc)
    c_late = datetime(2026, 3, 16, 10, 0, tzinfo=timezone.utc)

    recs = [
        _log_record(100, 0x02, 0x00),   # MFT record init
        _log_record(110, 0x0E, 0x0F, redo=_index_entry(
            81, "evil.exe", 5, created=c_early, modified=c_early,
            real=45056)),
        _log_record(120, 0x0E, 0x0F, redo=_index_entry(
            82, "wiped.dat", 5, created=c_early, modified=c_early,
            real=1024)),
        _log_record(130, 0x0F, 0x0E, redo=_index_entry(
            82, "wiped.dat", 5, created=c_early, modified=c_early)),
        _log_record(140, 0x14, 0x14, redo=_filename_attr(
            "report.docx", 5, created=c_late, modified=c_early, real=8192)),
        _log_record(150, 0x0F, 0x0E, redo=_index_entry(
            90, "notes.txt", 5, created=c_early, modified=c_early)),
    ]
    return _rstr_page() + _rstr_page() + _rcrd_page(recs)
