"""A small, read-only parser for the Application Compatibility ``.sdb`` format.

An SDB is a 12-byte header (major / minor version, magic ``sdbf``) followed
by a tree of tags.  Each tag is a 16-bit value whose top nibble is the
storent type:

    0x1xxx NULL     no data
    0x2xxx BYTE      1 byte
    0x3xxx WORD      2 bytes
    0x4xxx DWORD     4 bytes
    0x5xxx QWORD     8 bytes  (FILETIMEs live here)
    0x6xxx STRINGREF u32 offset into the string table
    0x7xxx LIST      u32 length, then child tags
    0x8xxx STRING    u32 length, then UTF-16LE
    0x9xxx BINARY    u32 length, then bytes

The string table (tag 0x7801) holds 0x8801 STRING items; a STRINGREF is a
byte offset from the start of the table's child data.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

MAGIC = 0x66626473  # 'sdbf'


class SdbError(Exception):
    pass


def _wz(raw: bytes) -> str:
    """Decode UTF-16LE, cutting at the first null unit on an even boundary."""
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            raw = raw[:i]
            break
    return raw.decode("utf-16-le", "replace")


TAGS = {
    0x7001: "DATABASE", 0x7002: "LIBRARY", 0x7003: "INEXCLUDE",
    0x7004: "SHIM", 0x7005: "PATCH", 0x7006: "APP", 0x7007: "EXE",
    0x7008: "MATCHING_FILE", 0x7009: "SHIM_REF", 0x700A: "PATCH_REF",
    0x700B: "LAYER", 0x700C: "FILE", 0x700D: "APPHELP",
    0x700E: "LINK", 0x700F: "DATA", 0x7010: "MSI_TRANSFORM_REF",
    0x7011: "MSI_PACKAGE", 0x7012: "FLAG", 0x7801: "STRINGTABLE",
    0x6001: "NAME", 0x6002: "DESCRIPTION", 0x6003: "MODULE", 0x6004: "API",
    0x6005: "VENDOR", 0x6006: "APP_NAME", 0x6007: "COMMAND_LINE",
    0x6008: "COMPANY_NAME", 0x6009: "DLLFILE", 0x600A: "WILDCARD_NAME",
    0x6022: "PRODUCT_NAME", 0x6023: "PRODUCT_VERSION",
    0x6024: "FILE_DESCRIPTION", 0x6025: "FILE_VERSION",
    0x6026: "ORIGINAL_FILENAME", 0x6027: "INTERNAL_NAME", 0x6028: "LEGAL",
    0x6001: "NAME",
    0x8801: "STRINGTABLE_ITEM",
    0x4001: "SIZE", 0x4002: "OFFSET", 0x4003: "CHECKSUM", 0x4004: "BIN_FILE_VERSION",
    0x4005: "BIN_PRODUCT_VERSION", 0x4006: "MODULE_TYPE",
    0x4007: "VERFILEDATEHI", 0x4008: "VERFILEDATELO", 0x4009: "VERFILEOS",
    0x400A: "VERFILETYPE", 0x400B: "PE_CHECKSUM", 0x400C: "PREVOSMAJORVER",
    0x4010: "LINKER_VERSION", 0x4017: "LINK_DATE", 0x4018: "UPTO_LINK_DATE",
    0x4020: "CRC_CHECKSUM", 0x4021: "MAGIC1", 0x4022: "EXE_TYPE",
    0x5001: "TIME", 0x5002: "BIN_FILE_VERSION_Q",
    0x3801: "TAGID", 0x9002: "PATCH_BITS", 0x9003: "FILE_BITS",
    0x9004: "EXE_ID", 0x9007: "DATABASE_ID", 0x9010: "INDEX_BITS",
    0x9005: "MSI_PACKAGE_ID", 0x9006: "DATABASE_ID2",
    0x2007: "OS_PLATFORM",
}


@dataclass
class Node:
    tag: int
    name: str
    type: int
    value: object = None
    children: list = field(default_factory=list)
    offset: int = 0

    def get(self, name: str):
        for c in self.children:
            if c.name == name:
                return c
        return None

    def getv(self, name: str, default=None):
        c = self.get(name)
        return c.value if c is not None else default

    def all(self, name: str):
        return [c for c in self.children if c.name == name]

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


class Sdb:
    def __init__(self, data: bytes):
        if len(data) < 12:
            raise SdbError("file too small")
        self.major, self.minor, magic = struct.unpack_from("<III", data, 0)
        if magic != MAGIC:
            raise SdbError("bad magic (not an .sdb)")
        self.data = data
        self._st_start = self._find_stringtable()
        self.root = Node(0x7001, "ROOT", 0x7000, offset=12)
        self.root.children = self._parse_list(12, len(data), depth=0)

    # -- string table -------------------------------------------------
    def _find_stringtable(self) -> int:
        pos = 12
        data = self.data
        while pos + 6 <= len(data):
            tag = struct.unpack_from("<H", data, pos)[0]
            ttype = tag & 0xF000
            pos += 2
            if ttype in (0x7000, 0x8000, 0x9000):
                size = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                if tag == 0x7801:
                    return pos
                pos += size
            elif ttype == 0x1000:
                pass
            elif ttype == 0x2000:
                pos += 1
            elif ttype == 0x3000:
                pos += 2
            elif ttype in (0x4000, 0x6000):
                pos += 4
            elif ttype == 0x5000:
                pos += 8
            else:
                break
        return -1

    def _string_at(self, ref: int) -> str:
        if self._st_start < 0:
            return ""
        p = self._st_start + ref
        d = self.data
        if p + 6 > len(d):
            return ""
        tag = struct.unpack_from("<H", d, p)[0]
        if tag & 0xF000 != 0x8000:
            return ""
        size = struct.unpack_from("<I", d, p + 2)[0]
        return _wz(d[p + 6:p + 6 + size])

    # -- tag tree ---------------------------------------------------
    def _parse_list(self, start: int, end: int, depth: int) -> list[Node]:
        out: list[Node] = []
        pos = start
        d = self.data
        if depth > 40:
            return out
        while pos + 2 <= end:
            tag = struct.unpack_from("<H", d, pos)[0]
            if tag == 0:
                break
            ttype = tag & 0xF000
            name = TAGS.get(tag, f"TAG_{tag:04X}")
            node = Node(tag, name, ttype, offset=pos)
            pos += 2
            try:
                if ttype == 0x1000:
                    node.value = None
                elif ttype == 0x2000:
                    node.value = d[pos]
                    pos += 1
                elif ttype == 0x3000:
                    node.value = struct.unpack_from("<H", d, pos)[0]
                    pos += 2
                elif ttype == 0x4000:
                    node.value = struct.unpack_from("<I", d, pos)[0]
                    pos += 4
                elif ttype == 0x5000:
                    node.value = struct.unpack_from("<Q", d, pos)[0]
                    pos += 8
                elif ttype == 0x6000:
                    ref = struct.unpack_from("<I", d, pos)[0]
                    node.value = self._string_at(ref)
                    pos += 4
                elif ttype == 0x7000:
                    size = struct.unpack_from("<I", d, pos)[0]
                    pos += 4
                    cend = min(pos + size, end)
                    node.children = self._parse_list(pos, cend, depth + 1)
                    pos += size
                elif ttype == 0x8000:
                    size = struct.unpack_from("<I", d, pos)[0]
                    pos += 4
                    node.value = _wz(d[pos:pos + size])
                    pos += size
                elif ttype == 0x9000:
                    size = struct.unpack_from("<I", d, pos)[0]
                    pos += 4
                    node.value = d[pos:pos + size]
                    pos += size
                else:
                    break
            except (struct.error, IndexError):
                break
            out.append(node)
        return out


def as_guid(b) -> str:
    if not isinstance(b, (bytes, bytearray)) or len(b) != 16:
        return ""
    try:
        return str(uuid.UUID(bytes_le=bytes(b)))
    except ValueError:
        return ""
