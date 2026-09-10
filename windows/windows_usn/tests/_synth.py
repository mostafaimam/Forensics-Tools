"""Synthetic $UsnJrnl:$J stream for the windows_usn test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

R = {
    "DATA_OVERWRITE": 0x1, "DATA_EXTEND": 0x2, "DATA_TRUNCATION": 0x4,
    "FILE_CREATE": 0x100, "FILE_DELETE": 0x200,
    "RENAME_OLD_NAME": 0x1000, "RENAME_NEW_NAME": 0x2000,
    "BASIC_INFO_CHANGE": 0x8000, "SECURITY_CHANGE": 0x800,
    "CLOSE": 0x80000000,
}


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def record(usn, dt, file_ref, parent_ref, reason, name, attrs=0x20,
           major=2) -> bytes:
    nm = name.encode("utf-16-le")
    if major == 2:
        head = struct.pack("<HHQQ", major, 0, file_ref, parent_ref)
        rest_off = 8 + 4 + len(head)
    body = struct.pack("<QQIIII", usn, ft(dt), reason, 0, 0, attrs)
    name_off = 0x3C
    fixed = struct.pack("<HH", len(nm), name_off) + body
    # v2 record: 0x00 len, 0x04 major, 0x06 minor, 0x08 fref, 0x10 pref,
    # 0x18 usn, 0x20 ts, 0x28 reason, 0x2c source, 0x30 secid, 0x34 attrs,
    # 0x38 namelen, 0x3a nameoff, 0x3c name
    rec = bytearray(0x3C)
    struct.pack_into("<HH", rec, 4, major, 0)
    struct.pack_into("<QQ", rec, 8, file_ref, parent_ref)
    struct.pack_into("<Q", rec, 0x18, usn)
    struct.pack_into("<Q", rec, 0x20, ft(dt))
    struct.pack_into("<IIII", rec, 0x28, reason, 0, 0, attrs)
    struct.pack_into("<HH", rec, 0x38, len(nm), 0x3C)
    rec += nm
    while len(rec) % 8:
        rec += b"\x00"
    struct.pack_into("<I", rec, 0, len(rec))
    return bytes(rec)


def ref(entry, seq=1):
    return (seq << 48) | entry


def build_stream() -> bytes:
    t0 = datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc)
    recs = []
    u = 0x1000

    def add(dt, fe, pe, reason, name, attrs=0x20):
        nonlocal u
        recs.append(record(u, dt, ref(fe), ref(pe), reason, name, attrs))
        u += 0x60

    # normal doc edit
    add(t0, 200, 100, R["DATA_EXTEND"], "notes.docx")
    add(t0, 200, 100, R["DATA_EXTEND"] | R["CLOSE"], "notes.docx")
    # dropped payload in Temp: create + write + close
    add(t0 + timedelta(minutes=5), 201, 101, R["FILE_CREATE"], "agent.exe")
    add(t0 + timedelta(minutes=5), 201, 101,
        R["FILE_CREATE"] | R["DATA_EXTEND"] | R["CLOSE"], "agent.exe")
    # then deleted quickly
    add(t0 + timedelta(minutes=9), 201, 101,
        R["FILE_DELETE"] | R["CLOSE"], "agent.exe")
    # rename
    add(t0 + timedelta(minutes=12), 202, 100, R["RENAME_OLD_NAME"],
        "report_draft.docx")
    add(t0 + timedelta(minutes=12), 202, 100,
        R["RENAME_NEW_NAME"] | R["CLOSE"], "report_final.docx")
    # attribute-only change (timestomp-adjacent)
    add(t0 + timedelta(minutes=20), 203, 101,
        R["BASIC_INFO_CHANGE"] | R["CLOSE"], "loader.dll",
        attrs=0x22)

    # mass-delete burst
    for i in range(18):
        add(t0 + timedelta(minutes=40, seconds=i * 2), 300 + i, 105,
            R["FILE_DELETE"] | R["CLOSE"], f"cache_{i:03d}.tmp")

    # leading sparse region + records
    return b"\x00" * 512 + b"".join(recs)


def build_mft() -> bytes:
    """Tiny $MFT so entry 100/101/105 resolve to a path."""
    rec_size = 1024
    out = bytearray()

    def entry(name, parent):
        r = bytearray(rec_size)
        r[:4] = b"FILE"
        struct.pack_into("<H", r, 0x14, 0x38)     # first attr offset
        off = 0x38
        nm = name.encode("utf-16-le")
        content = struct.pack("<Q", (1 << 48) | parent) + b"\x00" * 0x38 \
            + struct.pack("<BB", len(name), 3) + nm
        struct.pack_into("<I", r, off, 0x30)      # $FILE_NAME
        struct.pack_into("<I", r, off + 4, 0x18 + len(content) + 8)
        struct.pack_into("<H", r, off + 0x14, 0x18)   # content offset
        r[off + 0x18:off + 0x18 + len(content)] = content
        end = off + 0x18 + len(content)
        end += (8 - end % 8) % 8
        struct.pack_into("<I", r, end, 0xFFFFFFFF)
        return bytes(r)

    layout = [("", 5), ("Windows", 5), ("Temp", 100), ("Users", 5),
              ("victim", 103)]
    # entries 0..4 padding, then real entries at fixed indices
    entries = {5: (".", 5), 100: ("Windows", 5), 101: ("Temp", 100),
               103: ("Users", 5), 105: ("Prefetch", 100)}
    maxe = max(entries)
    for i in range(maxe + 1):
        if i in entries:
            nm, parent = entries[i]
            out += entry(nm, parent)
        else:
            out += b"\x00" * rec_size
    return bytes(out)
