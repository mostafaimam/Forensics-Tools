"""Find and decode `regf` hive base-block headers in physical memory."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MAGIC = re.compile(rb"regf")


def _filetime(v: int) -> str:
    if not v or v > 0x7FFF_FFFF_FFFF_FFFF:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def _decode_name(raw: bytes) -> str:
    end = raw.find(b"\x00\x00")
    if end >= 0 and end % 2:
        end += 1
    text = raw[:end if end >= 0 else len(raw)]
    try:
        s = text.decode("utf-16-le", "replace")
    except UnicodeDecodeError:
        return ""
    s = s.split("\x00")[0]
    return s if all(c.isprintable() or c in "\\/:" for c in s) else ""


@dataclass
class HiveHeader:
    phys_offset: int
    seq1: int
    seq2: int
    last_written: str
    major: int
    minor: int
    root_cell: int
    length: int
    file_name: str

    @property
    def dirty(self) -> bool:
        return self.seq1 != self.seq2

    def row(self) -> dict:
        return {
            "phys_offset": f"{self.phys_offset:#x}", "file_name":
                self.file_name or "(unresolved)", "dirty":
                "yes" if self.dirty else "no", "seq1": self.seq1,
            "seq2": self.seq2, "last_written": self.last_written,
            "version": f"{self.major}.{self.minor}", "length": self.length,
        }


def _parse_header(buf: bytes, base: int) -> HiveHeader | None:
    if len(buf) < 0x200 or buf[:4] != b"regf":
        return None
    try:
        seq1, seq2 = struct.unpack_from("<II", buf, 4)
        last_written = struct.unpack_from("<Q", buf, 0x0C)[0]
        major, minor = struct.unpack_from("<II", buf, 0x14)
        root_cell, length = struct.unpack_from("<II", buf, 0x24)
    except struct.error:
        return None
    if major not in (1,) or minor not in (2, 3, 4, 5, 6):
        return None
    # the filename field is nominally 64 bytes at 0x30, but some builds
    # store a longer path; read generously up to the checksum at 0x1FC
    name = _decode_name(buf[0x30:0x1FC])
    return HiveHeader(phys_offset=base, seq1=seq1, seq2=seq2,
                      last_written=_filetime(last_written), major=major,
                      minor=minor, root_cell=root_cell, length=length,
                      file_name=name)


def scan(img, *, progress=None) -> list[HiveHeader]:
    out: list[HiveHeader] = []
    seen_offsets = set()
    scanned = 0
    for base, block in img.stream_runs():
        for m in _MAGIC.finditer(block):
            off = base + m.start()
            if off in seen_offsets:
                continue
            seen_offsets.add(off)
            # header may start slightly before this hit if truncated by a
            # run boundary; also try reading straight from the image
            try:
                buf = img.read_physical(off, 0x1000)
            except Exception:  # noqa: BLE001
                continue
            hh = _parse_header(buf, off)
            if hh:
                out.append(hh)
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)

    # de-dup identical (name, seq1, seq2) triples - the same hive header
    # is often mapped at more than one physical location
    best: dict[tuple, HiveHeader] = {}
    for h in out:
        key = (h.file_name.lower(), h.seq1, h.seq2, h.last_written)
        if key not in best or h.phys_offset < best[key].phys_offset:
            best[key] = h
    return sorted(best.values(), key=lambda h: h.file_name.lower())
