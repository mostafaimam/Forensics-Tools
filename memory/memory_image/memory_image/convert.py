"""Transcode a memory image between raw / lime / padded layouts."""

from __future__ import annotations

import struct
from pathlib import Path

from memory_image.loader import MemoryImage

_LIME_HDR = struct.Struct("<IIQQQ")
_MAGIC = 0x4C694D45


def _lime_header(start: int, end_inclusive: int) -> bytes:
    return _LIME_HDR.pack(_MAGIC, 1, start, end_inclusive, 0)


def convert(img: MemoryImage, out_path: str, fmt: str, *, progress=None) -> int:
    out = Path(out_path)
    total = img.mapped_size
    done = 0
    written = 0
    with out.open("wb") as of:
        if fmt == "raw":
            for _phys, block in img.stream_runs():
                of.write(block)
                written += len(block)
                done += len(block)
                if progress:
                    progress(done, total)
        elif fmt == "lime":
            for run in img.runs:
                hdr = _lime_header(run.phys_start, run.phys_end - 1)
                of.write(hdr)
                written += len(hdr)
                pos = 0
                while pos < run.size:
                    n = min(8 << 20, run.size - pos)
                    of.write(img.read_physical(run.phys_start + pos, n))
                    written += n
                    done += n
                    pos += n
                    if progress:
                        progress(done, total)
        elif fmt == "padded":
            for run in img.runs:
                of.seek(run.phys_start)
                pos = 0
                while pos < run.size:
                    n = min(8 << 20, run.size - pos)
                    of.write(img.read_physical(run.phys_start + pos, n))
                    written += n
                    done += n
                    pos += n
                    if progress:
                        progress(done, total)
            written = of.tell()
        else:
            raise ValueError(f"unknown format: {fmt}")
    return written


def carve(img: MemoryImage, out_path: str, phys_offset: int, size: int, *,
          progress=None) -> int:
    written = 0
    with open(out_path, "wb") as of:
        pos = phys_offset
        end = phys_offset + size
        while pos < end:
            n = min(8 << 20, end - pos)
            of.write(img.read_physical(pos, n))
            written += n
            pos += n
            if progress:
                progress(written, size)
    return written
