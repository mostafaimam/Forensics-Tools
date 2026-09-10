"""Build synthetic .shd + .spl spool files."""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO


def build_shd(*, printer="HP LaserJet on FILESRV",
              machine="\\\\WKS-42", user="jsmith",
              document="Q3 salary review - CONFIDENTIAL.docx",
              datatype="RAW", processor="winprint",
              driver="HP Universal Printing PCL 6",
              job_id=7, submit=(2026, 3, 16, 1, 15, 30, 5)) -> bytes:
    hdr = bytearray(0x80)
    struct.pack_into("<I", hdr, 0x00, 0x00010000)     # signature
    struct.pack_into("<I", hdr, 0x08, job_id)
    struct.pack_into("<I", hdr, 0x0C, 1)              # priority

    pool = bytearray()
    base = 0x90

    def add(s: str) -> int:
        nonlocal pool
        off = base + len(pool)
        pool += s.encode("utf-16-le") + b"\x00\x00"
        return off

    slots = [(0x18, printer), (0x1C, machine), (0x20, user),
             (0x24, "jsmith"), (0x28, document), (0x2C, datatype),
             (0x30, processor), (0x34, ""), (0x38, driver)]
    for pos, val in slots:
        struct.pack_into("<I", hdr, pos, add(val) if val else 0)

    # SYSTEMTIME at 0x70: year, month, dow, day, hour, minute, second, ms
    y, mo, d, h, mi, s, dow = submit
    struct.pack_into("<8H", hdr, 0x70, y, mo, dow, d, h, mi, s, 0)

    out = bytes(hdr) + b"\x00" * (base - 0x80) + bytes(pool)
    return out


def build_spl_xps(pages=2) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("FixedDocumentSequence.fdseq", "<x/>")
        z.writestr("Documents/1/FixedDocument.fdoc", "<x/>")
        for i in range(1, pages + 1):
            z.writestr(f"Documents/1/Pages/{i}.fpage", "<FixedPage/>")
    return buf.getvalue()


def build_spl_emf(pages=1) -> bytes:
    out = bytearray()
    for _ in range(pages):
        # EMR_HEADER: type=1, size=88, then bounds/frame..., 'EMF' sig at 0x28
        rec = bytearray(88)
        struct.pack_into("<II", rec, 0, 1, 88)
        struct.pack_into("<I", rec, 0x28, 0x464D4520)   # ' EMF'
        out += rec
        # EMR_EOF: type=14, size=20
        eof = bytearray(20)
        struct.pack_into("<II", eof, 0, 14, 20)
        out += eof
    return bytes(out)


def build_spl_ps() -> bytes:
    return (b"%!PS-Adobe-3.0\n%%Pages: 3\n%%Page: 1 1\nshowpage\n"
            b"%%Page: 2 2\nshowpage\n%%Page: 3 3\nshowpage\n%%EOF\n")
