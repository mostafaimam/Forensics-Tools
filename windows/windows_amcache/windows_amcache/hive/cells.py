"""Parse the keyed cell structures: ``nk``, ``vk``, subkey lists, ``db``."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from windows_amcache.hive.regf import filetime_to_utc
from windows_amcache.hive.values import decode, type_name

NK_COMPRESSED_NAME = 0x0020
VK_COMPRESSED_NAME = 0x0001
BIG_DATA_THRESHOLD = 16344


def _name(raw: bytes, ascii_flag: bool) -> str:
    if ascii_flag:
        return raw.decode("latin-1", "replace")
    return raw.decode("utf-16-le", "replace")


@dataclass
class KeyNode:
    offset: int
    flags: int
    last_written: object
    parent_offset: int
    subkey_count: int
    subkeys_list_offset: int
    value_count: int
    values_list_offset: int
    security_offset: int
    class_offset: int
    name: str
    allocated: bool = True

    @property
    def is_root(self) -> bool:
        return bool(self.flags & 0x000C)

    @classmethod
    def parse(cls, payload: bytes, offset: int, allocated: bool = True) -> "KeyNode":
        if payload[:2] != b"nk" or len(payload) < 0x50:
            raise ValueError("not an nk cell")
        flags = struct.unpack_from("<H", payload, 0x02)[0]
        ft = struct.unpack_from("<Q", payload, 0x04)[0]
        parent = struct.unpack_from("<I", payload, 0x10)[0]
        n_sub = struct.unpack_from("<I", payload, 0x14)[0]
        sub_list = struct.unpack_from("<I", payload, 0x1C)[0]
        n_val = struct.unpack_from("<I", payload, 0x24)[0]
        val_list = struct.unpack_from("<I", payload, 0x28)[0]
        sec = struct.unpack_from("<I", payload, 0x2C)[0]
        klass = struct.unpack_from("<I", payload, 0x30)[0]
        name_len = struct.unpack_from("<H", payload, 0x48)[0]
        name_raw = payload[0x4C:0x4C + name_len]
        name = _name(name_raw, bool(flags & NK_COMPRESSED_NAME))
        return cls(offset, flags, filetime_to_utc(ft), parent, n_sub, sub_list,
                   n_val, val_list, sec, klass, name, allocated)


@dataclass
class ValueNode:
    offset: int
    name: str
    data_type: int
    data: object
    raw_data: bytes
    resident: bool = False
    allocated: bool = True

    @property
    def type_name(self) -> str:
        return type_name(self.data_type)

    @classmethod
    def parse(cls, payload: bytes, offset: int, hive, allocated: bool = True) -> "ValueNode":
        if payload[:2] != b"vk" or len(payload) < 0x14:
            raise ValueError("not a vk cell")
        name_len = struct.unpack_from("<H", payload, 0x02)[0]
        data_size = struct.unpack_from("<I", payload, 0x04)[0]
        data_offset = struct.unpack_from("<I", payload, 0x08)[0]
        data_type = struct.unpack_from("<I", payload, 0x0C)[0]
        flags = struct.unpack_from("<H", payload, 0x10)[0]
        name_raw = payload[0x14:0x14 + name_len]
        name = _name(name_raw, bool(flags & VK_COMPRESSED_NAME)) if name_len \
            else "(default)"

        resident = bool(data_size & 0x80000000)
        real_size = data_size & 0x7FFFFFFF
        raw = b""
        if resident:
            raw = struct.pack("<I", data_offset)[:real_size]
        elif real_size == 0:
            raw = b""
        elif real_size > BIG_DATA_THRESHOLD:
            raw = _read_big_data(hive, data_offset, real_size)
        else:
            try:
                raw = hive.cell_data(data_offset)[:real_size]
            except Exception:
                raw = b""
        return cls(offset, name, data_type, decode(data_type, raw), raw,
                   resident, allocated)


def _read_big_data(hive, offset: int, total: int) -> bytes:
    try:
        db = hive.cell_data(offset)
    except Exception:
        return b""
    if db[:2] != b"db":
        return b""
    n_seg = struct.unpack_from("<H", db, 0x02)[0]
    seg_list_off = struct.unpack_from("<I", db, 0x04)[0]
    try:
        seg_list = hive.cell_data(seg_list_off)
    except Exception:
        return b""
    out = bytearray()
    for i in range(n_seg):
        if 4 * i + 4 > len(seg_list):
            break
        so = struct.unpack_from("<I", seg_list, 4 * i)[0]
        try:
            out += hive.cell_data(so)[:BIG_DATA_THRESHOLD]
        except Exception:
            break
    return bytes(out[:total])


def iter_subkey_offsets(hive, list_offset: int, _depth: int = 0):
    """Yield nk cell offsets from an lf / lh / li / ri list (recursively)."""
    if list_offset in (0, 0xFFFFFFFF) or _depth > 32:
        return
    try:
        data = hive.cell_data(list_offset)
    except Exception:
        return
    sig = data[:2]
    count = struct.unpack_from("<H", data, 0x02)[0]
    if sig in (b"lf", b"lh"):
        for i in range(count):
            base = 0x04 + i * 8
            if base + 4 > len(data):
                break
            yield struct.unpack_from("<I", data, base)[0]
    elif sig == b"li":
        for i in range(count):
            base = 0x04 + i * 4
            if base + 4 > len(data):
                break
            yield struct.unpack_from("<I", data, base)[0]
    elif sig == b"ri":
        for i in range(count):
            base = 0x04 + i * 4
            if base + 4 > len(data):
                break
            sub = struct.unpack_from("<I", data, base)[0]
            yield from iter_subkey_offsets(hive, sub, _depth + 1)


def iter_value_offsets(hive, list_offset: int, count: int):
    if list_offset in (0, 0xFFFFFFFF) or count == 0:
        return
    try:
        data = hive.cell_data(list_offset)
    except Exception:
        return
    for i in range(count):
        if 4 * i + 4 > len(data):
            break
        yield struct.unpack_from("<I", data, 4 * i)[0]
