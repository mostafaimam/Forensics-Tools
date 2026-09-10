"""Identify and measure a ``.spl`` spool-data payload."""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from io import BytesIO


@dataclass
class SplData:
    source: str
    fmt: str = "unknown"
    pages: int = 0
    bytes_total: int = 0
    detail: str = ""
    xps_parts: list = field(default_factory=list)
    parse_error: str = ""

    def row(self) -> dict:
        return {"spl_format": self.fmt, "spl_pages": self.pages,
                "spl_bytes": self.bytes_total, "spl_detail": self.detail,
                "source": self.source}


def _emf_pages(data: bytes) -> int:
    """Count EMR_HEADER records inside a spooled EMF stream."""
    pages, pos, n = 0, 0, len(data)
    # spool EMF is wrapped: page = [u32 recordType==1 EMR_HEADER ...]
    while pos + 8 <= n:
        rtype, rsize = struct.unpack_from("<II", data, pos)
        if rtype == 1 and 40 <= rsize <= 0x100000:
            pages += 1
            pos += rsize
            # skip to EMR_EOF (type 14)
            while pos + 8 <= n:
                t2, s2 = struct.unpack_from("<II", data, pos)
                if s2 < 8 or s2 > 0x4000000:
                    pos = n
                    break
                pos += s2
                if t2 == 14:
                    break
        else:
            pos += 4
    return pages


def parse_spl(data: bytes, source: str) -> SplData:
    d = SplData(source=source, bytes_total=len(data))
    head = data[:64]

    if head[:2] == b"PK":
        d.fmt = "XPS/OpenXPS"
        try:
            zf = zipfile.ZipFile(BytesIO(data))
            fpages = [n for n in zf.namelist()
                      if n.lower().endswith(".fpage")]
            d.xps_parts = fpages
            d.pages = len(fpages)
            docs = [n for n in zf.namelist()
                    if n.lower().endswith(".fdoc")]
            d.detail = f"{len(fpages)} fixed page(s), {len(docs)} document(s)"
        except zipfile.BadZipFile as e:
            d.parse_error = f"bad XPS zip: {e}"
        return d

    if head[:4] == b"%!PS" or b"%!PS-Adobe" in head:
        d.fmt = "PostScript"
        d.pages = data.count(b"%%Page:") or data.count(b"showpage")
        d.detail = f"~{d.pages} page marker(s)"
        return d

    if head[:4] == b"%PDF":
        d.fmt = "PDF"
        d.pages = data.count(b"/Type /Page") + data.count(b"/Type/Page")
        return d

    if head[:1] == b"\x1b" and (b"\x1bE" in head or b"\x1b%-12345X" in data[:32]):
        d.fmt = "PCL"
        d.pages = data.count(b"\x0c")
        return d

    # spooled EMF: often begins with a small wrapper then 'EMF' at 0x28 of
    # the first EMR_HEADER, or the raw EMR_HEADER (type 1)
    if b"\x20EMF" in data[:2048] or struct.unpack_from("<I", data, 0)[0] == 1:
        d.fmt = "EMF"
        d.pages = _emf_pages(data)
        d.detail = f"{d.pages} EMF page(s)"
        return d

    # SPL job wrapper (type 0x00000001 page descriptors) / raw
    if len(data) >= 8 and struct.unpack_from("<I", data, 0)[0] in (1, 2, 3):
        d.fmt = "SPL-wrapped"
        d.pages = _emf_pages(data)
        return d

    d.fmt = "raw / text"
    d.detail = f"{len(data)} bytes, no recognised print format"
    return d
