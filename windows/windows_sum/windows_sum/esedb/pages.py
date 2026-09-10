"""ESE database header + page / tag parsing.

Layout follows the widely-implemented reading of the EDB format (as in
libesedb and impacket's ``ese.py``): a 40-byte page header, an optional
40-byte extended header for Vista+ databases with a page size above 8 KiB,
and a page-tag array that grows backwards from the end of the page.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = 0x89ABCDEF

# page flags
FLAG_ROOT = 0x0001
FLAG_LEAF = 0x0002
FLAG_PARENT = 0x0004
FLAG_EMPTY = 0x0008
FLAG_SPACE_TREE = 0x0020
FLAG_INDEX = 0x0040
FLAG_LONG_VALUE = 0x0080
FLAG_NEW_RECORD_FORMAT = 0x2000


class EseError(Exception):
    pass


@dataclass
class DbHeader:
    format_version: int
    format_revision: int
    page_size: int
    state: int
    file_type: int


def parse_header(data: bytes) -> DbHeader:
    if len(data) < 668:
        raise EseError("file too small to be an ESE database")
    if struct.unpack_from("<I", data, 4)[0] != MAGIC:
        raise EseError("not an ESE database (bad magic at offset 4)")
    fmt_version = struct.unpack_from("<I", data, 8)[0]
    file_type = struct.unpack_from("<I", data, 12)[0]
    fmt_revision = struct.unpack_from("<I", data, 0xE8)[0]
    page_size = struct.unpack_from("<I", data, 0xEC)[0]
    state = struct.unpack_from("<I", data, 0x34)[0]
    if page_size not in (2048, 4096, 8192, 16384, 32768):
        page_size = 4096
    return DbHeader(fmt_version, fmt_revision, page_size, state, file_type)


@dataclass
class Tag:
    offset: int
    size: int
    flags: int          # 0..7 : 1=value defined, 2=common, 4=derived


@dataclass
class Page:
    number: int
    flags: int
    next_page: int
    prev_page: int
    father_page: int
    tags: list
    data: bytes         # page bytes after the header(s)
    page_size: int
    header_size: int

    def is_leaf(self) -> bool:
        return bool(self.flags & FLAG_LEAF)

    def is_root(self) -> bool:
        return bool(self.flags & FLAG_ROOT)

    def is_empty(self) -> bool:
        return bool(self.flags & FLAG_EMPTY)

    def is_space_tree(self) -> bool:
        return bool(self.flags & FLAG_SPACE_TREE)

    def is_branch(self) -> bool:
        return not self.is_leaf() and not self.is_empty()

    def tag_bytes(self, i: int) -> bytes:
        t = self.tags[i]
        return self.data[t.offset:t.offset + t.size]


class Pager:
    def __init__(self, raw: bytes, header: DbHeader):
        self.raw = raw
        self.header = header
        self.page_size = header.page_size
        self.extended = (header.format_revision >= 0x11
                         and self.page_size > 8192)
        self.header_size = 80 if self.extended else 40

    def page_offset(self, number: int) -> int:
        return (number + 1) * self.page_size

    def read(self, number: int) -> Page:
        off = self.page_offset(number)
        raw = self.raw[off:off + self.page_size]
        if len(raw) < self.page_size:
            raise EseError(f"page {number} beyond end of file")

        prev_page = struct.unpack_from("<i", raw, 0x10)[0]
        next_page = struct.unpack_from("<i", raw, 0x14)[0]
        father = struct.unpack_from("<I", raw, 0x18)[0]
        first_avail_off = struct.unpack_from("<H", raw, 0x20)[0]  # noqa: F841
        tag_count = struct.unpack_from("<H", raw, 0x22)[0]
        flags = struct.unpack_from("<I", raw, 0x24)[0]

        hs = self.header_size
        data = raw[hs:]
        tags = self._tags(raw, tag_count, flags, hs)
        return Page(number, flags, next_page, prev_page, father, tags,
                    data, self.page_size, hs)

    def _tags(self, raw: bytes, count: int, page_flags: int,
              header_size: int) -> list[Tag]:
        tags: list[Tag] = []
        big = self.page_size > 8192
        avail = self.page_size - header_size
        for i in range(count):
            p = self.page_size - (i + 1) * 4
            if p < header_size:
                break
            size, offv = struct.unpack_from("<HH", raw, p)
            if big:
                size &= 0x7FFF
                offset = offv & 0x7FFF
                # tag flags live in bits 13-15 of the first word of the
                # entry data itself
                if 0 <= offset + 2 <= len(raw) - header_size:
                    first = struct.unpack_from("<H", raw,
                                               header_size + offset)[0]
                    flags = (first >> 13) & 0x7
                else:
                    flags = 0
            else:
                size &= 0x1FFF
                flags = (offv >> 13) & 0x7
                offset = offv & 0x1FFF
            if offset > avail or offset + size > avail + 4:
                # tolerate a slightly oversized last tag
                size = max(0, min(size, avail - offset))
            tags.append(Tag(offset, size, flags))
        return tags
