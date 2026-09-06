"""Build synthetic AppCompatCache blobs and a SYSTEM hive containing one."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from _hive_synth import HiveBuilder

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH).total_seconds()
               * 10_000_000)


def win10_blob(entries: list[tuple[str, datetime]]) -> bytes:
    out = bytearray(struct.pack("<I", 0x34))
    out += b"\x00" * (0x34 - len(out))
    for path, when in entries:
        p = path.encode("utf-16-le")
        payload = struct.pack("<H", len(p)) + p + struct.pack("<Q", ft(when)) \
            + struct.pack("<I", 0)
        out += b"10ts" + b"\x00\x00\x00\x00" + struct.pack("<I", len(payload))
        out += payload
    return bytes(out)


def win7_blob(entries: list[tuple[str, datetime, bool]]) -> bytes:
    num = len(entries)
    header = struct.pack("<II", 0xBADC0FEE, num) + b"\x00" * (0x80 - 8)
    entry_area = bytearray()
    path_area = bytearray()
    path_base = 0x80 + num * 32
    for path, when, executed in entries:
        p = path.encode("utf-16-le")
        path_off = path_base + len(path_area)
        entry_area += struct.pack("<HH", len(p), len(p))
        entry_area += struct.pack("<I", path_off)
        entry_area += struct.pack("<Q", ft(when))
        entry_area += struct.pack("<I", 0x2 if executed else 0x1)
        entry_area += struct.pack("<I", 0)          # data size
        entry_area += b"\x00" * 8                   # padding to 32
        path_area += p
    return header + bytes(entry_area) + bytes(path_area)


def system_hive_with_shimcache(blob: bytes,
                               control_set: str = "ControlSet001") -> bytes:
    b = HiveBuilder()
    v = b.vk("AppCompatCache", blob, 3)             # REG_BINARY
    vl = b.value_list([v])
    ac = b.nk("AppCompatCache", parent=0, values=1, val_list=vl)
    ac_list = b.lh([ac])
    sm = b.nk("Session Manager", parent=0, subkeys=1, sub_list=ac_list)
    sm_list = b.lh([sm])
    control = b.nk("Control", parent=0, subkeys=1, sub_list=sm_list)
    control_list = b.lh([control])
    cs = b.nk(control_set, parent=0, subkeys=1, sub_list=control_list)
    root_list = b.lh([cs])
    root = b.nk("ROOT", parent=0, flags=0x2C, subkeys=1, sub_list=root_list)
    return b.build(root)
