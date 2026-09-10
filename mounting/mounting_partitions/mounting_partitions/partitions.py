"""MBR and GPT partition-table parsing."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from mounting_partitions.formats.base import Image

_MBR_TYPES = {
    0x00: "empty", 0x05: "extended", 0x07: "NTFS/exFAT", 0x0B: "FAT32",
    0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x82: "Linux swap",
    0x83: "Linux", 0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xA8: "Apple UFS",
    0xAF: "Apple HFS+", 0xEE: "GPT protective", 0xEF: "EFI System",
    0xFD: "Linux RAID",
}

_GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "MS Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic data (NTFS/exFAT/FAT)",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "44479540-f297-41b2-9af7-d131d5f0458a": "Linux root (x86)",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "Linux root (x86-64)",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "48465300-0000-11aa-aa11-00306543ecac ": "Apple HFS+",
    "426f6f74-0000-11aa-aa11-00306543ecac": "Apple Boot",
}


@dataclass
class Partition:
    index: int
    scheme: str            # mbr | gpt
    start_offset: int      # bytes from the start of the image
    length: int            # bytes
    type_code: str         # hex byte (mbr) or GUID (gpt)
    type_label: str
    name: str = ""
    bootable: bool = False

    @property
    def start_lba(self) -> int:
        return self.start_offset // 512

    @property
    def end_offset(self) -> int:
        return self.start_offset + self.length


def _guid_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def parse_mbr(img: Image, sector: int = 512) -> list[Partition]:
    out: list[Partition] = []
    data = img.read(0, 512)
    if data[510:512] != b"\x55\xaa":
        return out
    for i in range(4):
        entry = data[446 + i * 16: 446 + i * 16 + 16]
        boot, _chs1, ptype, _chs2, lba, count = struct.unpack("<B3sB3sII", entry)
        if ptype == 0 or count == 0:
            continue
        if ptype in (0x05, 0x0F, 0x85):
            ext_base = lba * sector
            out.extend(_parse_ebr(img, ext_base, ext_base, sector, len(out)))
            continue
        out.append(Partition(
            index=len(out) + 1, scheme="mbr",
            start_offset=lba * sector, length=count * sector,
            type_code=f"0x{ptype:02X}",
            type_label=_MBR_TYPES.get(ptype, f"type 0x{ptype:02X}"),
            bootable=bool(boot & 0x80)))
    return out


def _parse_ebr(img: Image, ext_start: int, cur: int, sector: int,
               n: int) -> list[Partition]:
    out: list[Partition] = []
    seen = set()
    while cur and cur not in seen:
        seen.add(cur)
        data = img.read(cur, 512)
        if data[510:512] != b"\x55\xaa":
            break
        e0 = data[446:462]
        boot, _c1, ptype, _c2, lba, count = struct.unpack("<B3sB3sII", e0)
        if count:
            out.append(Partition(
                index=n + len(out) + 1, scheme="mbr",
                start_offset=cur + lba * sector, length=count * sector,
                type_code=f"0x{ptype:02X}",
                type_label=_MBR_TYPES.get(ptype, f"type 0x{ptype:02X}"),
                bootable=bool(boot & 0x80)))
        e1 = data[462:478]
        _b, _c1, _t, _c2, nlba, ncount = struct.unpack("<B3sB3sII", e1)
        if ncount == 0:
            break
        cur = ext_start + nlba * sector
    return out


def parse_gpt(img: Image, sector: int = 512) -> list[Partition]:
    hdr = img.read(sector, sector)
    if hdr[:8] != b"EFI PART":
        return []
    part_lba = struct.unpack_from("<Q", hdr, 72)[0]
    count = struct.unpack_from("<I", hdr, 80)[0]
    esize = struct.unpack_from("<I", hdr, 84)[0]
    if not (0 < count <= 512) or not (128 <= esize <= 4096):
        return []
    table = img.read(part_lba * sector, count * esize)
    out: list[Partition] = []
    for i in range(count):
        e = table[i * esize: i * esize + esize]
        if len(e) < 56:
            break
        type_guid = _guid_le(e[0:16])
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        name = e[56:128].decode("utf-16-le", "replace").split("\x00")[0]
        out.append(Partition(
            index=len(out) + 1, scheme="gpt",
            start_offset=first * sector,
            length=(last - first + 1) * sector,
            type_code=type_guid,
            type_label=_GPT_TYPES.get(type_guid, "unknown GUID"),
            name=name))
    return out


def detect(img: Image) -> tuple[str, list[Partition]]:
    """Return ("gpt"|"mbr"|"none", partitions)."""
    mbr = img.read(0, 512)
    if mbr[510:512] == b"\x55\xaa":
        types = [mbr[446 + i * 16 + 4] for i in range(4)]
        if 0xEE in types:
            gpt = parse_gpt(img)
            if gpt:
                return "gpt", gpt
        parts = parse_mbr(img)
        if parts:
            return "mbr", parts
    gpt = parse_gpt(img)
    if gpt:
        return "gpt", gpt
    return "none", []
