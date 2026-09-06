"""Parse a single MFT (FILE) record: fixups + attribute iteration."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SIGNATURE = b"FILE"
BAAD = b"BAAD"

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_END = 0xFFFFFFFF


class RecordError(ValueError):
    pass


@dataclass
class Attribute:
    type_id: int
    non_resident: bool
    name: str
    flags: int
    attr_id: int
    # resident
    content: bytes = b""
    # non-resident
    start_vcn: int = 0
    last_vcn: int = 0
    allocated_size: int = 0
    real_size: int = 0
    runlist_raw: bytes = b""


@dataclass
class MftRecord:
    number: int
    in_use: bool
    is_directory: bool
    sequence: int
    base_reference: int          # 0 if this is a base record
    attributes: list[Attribute] = field(default_factory=list)
    raw_ok: bool = True

    def by_type(self, type_id: int) -> list[Attribute]:
        return [a for a in self.attributes if a.type_id == type_id]


def apply_fixup(buf: bytearray, sector_size: int = 512) -> None:
    """Replace the last two bytes of every sector with the saved originals
    from the update-sequence array, verifying the update-sequence number."""
    usa_off = struct.unpack_from("<H", buf, 4)[0]
    usa_count = struct.unpack_from("<H", buf, 6)[0]
    if usa_count == 0:
        return
    usn = buf[usa_off:usa_off + 2]
    entries = usa_count - 1
    for i in range(entries):
        sec_end = (i + 1) * sector_size
        if sec_end > len(buf):
            break
        if bytes(buf[sec_end - 2:sec_end]) != bytes(usn):
            raise RecordError(f"fixup mismatch in sector {i}")
        orig = buf[usa_off + 2 + i * 2: usa_off + 2 + i * 2 + 2]
        buf[sec_end - 2:sec_end] = orig


def parse_record(raw: bytes, number: int, sector_size: int = 512) -> MftRecord:
    if len(raw) < 42:
        raise RecordError("record too small")
    sig = raw[:4]
    if sig == BAAD:
        raise RecordError("record marked BAAD")
    if sig != SIGNATURE:
        raise RecordError(f"bad signature {sig!r}")

    buf = bytearray(raw)
    raw_ok = True
    try:
        apply_fixup(buf, sector_size)
    except RecordError:
        raw_ok = False

    flags = struct.unpack_from("<H", buf, 22)[0]
    seq = struct.unpack_from("<H", buf, 16)[0]
    first_attr = struct.unpack_from("<H", buf, 20)[0]
    base_ref = struct.unpack_from("<Q", buf, 32)[0] & 0x0000FFFFFFFFFFFF

    rec = MftRecord(
        number=number,
        in_use=bool(flags & FLAG_IN_USE),
        is_directory=bool(flags & FLAG_DIRECTORY),
        sequence=seq,
        base_reference=base_ref,
        raw_ok=raw_ok,
    )

    off = first_attr
    n = len(buf)
    while off + 4 <= n:
        type_id = struct.unpack_from("<I", buf, off)[0]
        if type_id == ATTR_END or type_id == 0:
            break
        if off + 16 > n:
            break
        attr_len = struct.unpack_from("<I", buf, off + 4)[0]
        if attr_len < 16 or off + attr_len > n:
            break
        non_res = buf[off + 8]
        name_len = buf[off + 9]
        name_off = struct.unpack_from("<H", buf, off + 10)[0]
        attr_flags = struct.unpack_from("<H", buf, off + 12)[0]
        attr_id = struct.unpack_from("<H", buf, off + 14)[0]
        name = ""
        if name_len:
            name = bytes(buf[off + name_off: off + name_off + name_len * 2]) \
                .decode("utf-16-le", "replace")

        attr = Attribute(type_id=type_id, non_resident=bool(non_res),
                         name=name, flags=attr_flags, attr_id=attr_id)
        if non_res:
            attr.start_vcn = struct.unpack_from("<Q", buf, off + 16)[0]
            attr.last_vcn = struct.unpack_from("<Q", buf, off + 24)[0]
            run_off = struct.unpack_from("<H", buf, off + 32)[0]
            attr.allocated_size = struct.unpack_from("<Q", buf, off + 40)[0]
            attr.real_size = struct.unpack_from("<Q", buf, off + 48)[0]
            attr.runlist_raw = bytes(buf[off + run_off: off + attr_len])
        else:
            content_len = struct.unpack_from("<I", buf, off + 16)[0]
            content_off = struct.unpack_from("<H", buf, off + 20)[0]
            attr.content = bytes(buf[off + content_off:
                                     off + content_off + content_len])
        rec.attributes.append(attr)
        off += attr_len
    return rec
