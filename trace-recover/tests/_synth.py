"""Build a synthetic 'disk image' with known files at known offsets."""

from __future__ import annotations

import io
import sqlite3
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path


def tiny_png(width: int = 1, height: int = 1) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def tiny_bmp() -> bytes:
    pixels = b"\x00\x00\xff\x00"  # 1x1 24bpp + padding
    size = 14 + 40 + len(pixels)
    fh = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    ih = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 0, 0, 0, 0)
    return fh + ih + pixels


def tiny_gif() -> bytes:
    return (b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x80\x00\x00"
            + b"\x00\x00\x00\xff\xff\xff"                     # 2-entry GCT
            + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"     # image descriptor
            + b"\x02"                                          # LZW min code size
            + b"\x02\x44\x01"                                  # 1 sub-block
            + b"\x00"                                          # sub-block terminator
            + b"\x3b")                                         # trailer


def tiny_jpeg() -> bytes:
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"          # SOS, 1 component
    return (b"\xff\xd8"
            + b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + sos + b"\x35\x71\x2a\x9c\x04\x18" + b"\xff\xd9")


def sqlite_db() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        name = tf.name
    con = sqlite3.connect(name)
    con.execute("CREATE TABLE t(a, b)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, f"row{i}") for i in range(50)])
    con.commit()
    con.close()
    data = Path(name).read_bytes()
    Path(name).unlink()
    return data


def zip_blob() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", b"hello world\n" * 20)
        zf.writestr("dir/data.bin", bytes(range(256)) * 4)
    return buf.getvalue()


def build_image(path: Path) -> dict[str, tuple[int, int, bytes]]:
    """Returns {name: (offset, length, data)}."""
    junk = b"\xde\xad\xbe\xef" * 777
    parts = {
        "png": tiny_png(4, 4),
        "jpg": tiny_jpeg(),
        "bmp": tiny_bmp(),
        "gif": tiny_gif(),
        "sqlite": sqlite_db(),
        "zip": zip_blob(),
    }
    layout: dict[str, tuple[int, int, bytes]] = {}
    blob = bytearray(junk)
    for name, data in parts.items():
        blob += b"\x00" * 13          # unaligned padding
        layout[name] = (len(blob), len(data), data)
        blob += data
        blob += junk[: 500]
    path.write_bytes(bytes(blob))
    return layout
