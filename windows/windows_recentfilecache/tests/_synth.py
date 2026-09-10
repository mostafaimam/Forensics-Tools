"""Build a synthetic RecentFileCache.bcf."""

from __future__ import annotations

import struct

SIG = b"\xfe\xff\xee\xff"

PATHS = [
    "C:\\Program Files\\Internet Explorer\\iexplore.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe",
    "C:\\Users\\victim\\Downloads\\invoice.pdf.exe",
    "C:\\Users\\victim\\AppData\\Roaming\\a.scr",
    "C:\\Windows\\System32\\rundll32.exe",
]


def build_bcf(paths=None) -> bytes:
    paths = paths or PATHS
    out = bytearray(SIG + b"\x00" * 16)      # 20-byte header
    for p in paths:
        b = p.encode("utf-16-le")
        out += struct.pack("<I", len(p))     # char count, no terminator
        out += b + b"\x00\x00"               # string + end-of-string char
    return bytes(out)
