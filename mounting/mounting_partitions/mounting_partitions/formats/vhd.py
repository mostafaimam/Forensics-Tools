"""Microsoft VHD (``conectix``) - fixed and dynamic, read-only."""

from __future__ import annotations

import struct
from pathlib import Path

from mounting_partitions.formats.base import Image, ImageError

_FOOTER_COOKIE = b"conectix"
_DYN_COOKIE = b"cxsparse"
_UNALLOCATED = 0xFFFFFFFF


class VHDImage(Image):
    format_name = "vhd"

    def __init__(self, path: str | Path):
        self._fh = Path(path).open("rb")
        self._fh.seek(0, 2)
        file_size = self._fh.tell()
        if file_size < 512:
            raise ImageError("file too small for a VHD footer")
        self._fh.seek(file_size - 512)
        footer = self._fh.read(512)
        if footer[:8] != _FOOTER_COOKIE:
            # dynamic VHDs also keep a footer copy at offset 0
            self._fh.seek(0)
            footer = self._fh.read(512)
            if footer[:8] != _FOOTER_COOKIE:
                raise ImageError("no 'conectix' footer")
        self.disk_type = struct.unpack_from(">I", footer, 60)[0]
        self._size = struct.unpack_from(">Q", footer, 48)[0]
        data_offset = struct.unpack_from(">Q", footer, 16)[0]
        self.creator = footer[28:32].decode("latin-1", "replace")

        if self.disk_type == 2:                       # fixed
            self.subtype = "fixed"
            self._data_len = file_size - 512
            return
        if self.disk_type not in (3, 4):
            raise ImageError(f"unsupported VHD disk type {self.disk_type}")
        self.subtype = "dynamic" if self.disk_type == 3 else "differencing"
        self._fh.seek(data_offset)
        dyn = self._fh.read(1024)
        if dyn[:8] != _DYN_COOKIE:
            raise ImageError("dynamic header missing 'cxsparse'")
        self._table_offset = struct.unpack_from(">Q", dyn, 16)[0]
        self._max_entries = struct.unpack_from(">I", dyn, 28)[0]
        self._block_size = struct.unpack_from(">I", dyn, 32)[0]
        self._fh.seek(self._table_offset)
        bat_raw = self._fh.read(4 * self._max_entries)
        self._bat = list(struct.unpack(f">{self._max_entries}I",
                                       bat_raw.ljust(4 * self._max_entries, b"\xff")))
        self._sector_bitmap = ((self._block_size // 512) + 7) // 8
        self._sector_bitmap = (self._sector_bitmap + 511) // 512 * 512

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0:
            raise ImageError("negative offset")
        end = min(offset + length, self._size)
        if self.disk_type == 2:
            self._fh.seek(offset)
            data = self._fh.read(max(0, end - offset))
            return data.ljust(length, b"\x00") if offset + length <= self._size \
                else data
        out = bytearray()
        pos = offset
        while pos < end:
            blk = pos // self._block_size
            within = pos % self._block_size
            take = min(end - pos, self._block_size - within)
            sector = self._bat[blk] if blk < len(self._bat) else _UNALLOCATED
            if sector == _UNALLOCATED:
                out += b"\x00" * take
            else:
                self._fh.seek(sector * 512 + self._sector_bitmap + within)
                chunk = self._fh.read(take)
                out += chunk.ljust(take, b"\x00")
            pos += take
        if len(out) < length and offset + length <= self._size:
            out += b"\x00" * (length - len(out))
        return bytes(out)

    def close(self) -> None:
        self._fh.close()
