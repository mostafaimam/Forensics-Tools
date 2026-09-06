"""Write a fixed (flat) VHD around an :class:`Image` - a 512-byte footer.

A fixed VHD is just the raw disk bytes followed by a ``conectix`` footer, so
Windows ``Mount-DiskImage`` and macOS ``hdiutil`` can attach it read-only with
no conversion tools.
"""

from __future__ import annotations

import struct
import time
import uuid
from pathlib import Path

_COOKIE = b"conectix"
_VHD_EPOCH = 946684800          # 2000-01-01 00:00:00 UTC


def _chs(total_sectors: int) -> tuple[int, int, int]:
    """The geometry algorithm from the VHD spec appendix."""
    ts = min(total_sectors, 65535 * 16 * 255)
    if ts >= 65535 * 16 * 63:
        spt, heads, cth = 255, 16, ts // 255 // 16
    else:
        spt = 17
        cth = ts // spt
        heads = max((cth + 1023) // 1024, 4)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = ts // spt // heads
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = ts // spt // heads
    cylinders = cth // heads
    return cylinders & 0xFFFF, heads & 0xFF, spt & 0xFF


def _footer(size_bytes: int) -> bytes:
    f = bytearray(512)
    f[0:8] = _COOKIE
    struct.pack_into(">I", f, 8, 2)                       # features: reserved
    struct.pack_into(">I", f, 12, 0x00010000)             # format version
    struct.pack_into(">Q", f, 16, 0xFFFFFFFFFFFFFFFF)     # data offset (fixed)
    struct.pack_into(">I", f, 24, max(0, int(time.time()) - _VHD_EPOCH))
    f[28:32] = b"pyfr"                                    # creator app
    struct.pack_into(">I", f, 32, 0x000A0000)             # creator version
    f[36:40] = b"Wi2k"                                    # creator host OS
    struct.pack_into(">Q", f, 40, size_bytes)             # original size
    struct.pack_into(">Q", f, 48, size_bytes)             # current size
    cyl, heads, spt = _chs(size_bytes // 512)
    struct.pack_into(">HBB", f, 56, cyl, heads, spt)      # disk geometry
    struct.pack_into(">I", f, 60, 2)                      # disk type: fixed
    f[68:84] = uuid.uuid4().bytes                         # unique id
    f[84] = 0                                             # saved state
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)  # 1's-complement sum
    return bytes(f)


def write_fixed_vhd(image, out_path: str | Path, *, progress=None) -> Path:
    """Stream *image* (an :class:`Image`) to *out_path* + a fixed-VHD footer."""
    out = Path(out_path)
    total = image.size
    written = 0
    with out.open("wb") as fh:
        for chunk in image.stream():
            fh.write(chunk)
            written += len(chunk)
            if progress:
                progress(written, total)
        pad = (-written) % 512
        if pad:
            fh.write(b"\x00" * pad)
            written += pad
        fh.write(_footer(written))
    return out
