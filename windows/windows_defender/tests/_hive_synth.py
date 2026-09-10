"""Hand-build a minimal SOFTWARE hive with a Windows Defender subtree."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 4096


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


class HiveBuilder:
    def __init__(self) -> None:
        self.body = bytearray()
        self._cursor = 0x20

    def _alloc(self, payload: bytes, allocated: bool = True) -> int:
        size = (4 + len(payload) + 7) & ~7
        pad = size - 4 - len(payload)
        raw = struct.pack("<i", -size if allocated else size) + payload \
            + b"\x00" * pad
        offset = self._cursor
        self.body += raw
        self._cursor += size
        return offset

    def nk(self, name, *, parent=0, flags=0x20, subkeys=0,
           sub_list=0xFFFFFFFF, values=0, val_list=0xFFFFFFFF, when=None):
        when = when or datetime(2026, 1, 1, tzinfo=timezone.utc)
        nm = name.encode("latin-1")
        p = bytearray(0x4C + len(nm))
        p[0:2] = b"nk"
        struct.pack_into("<H", p, 0x02, flags)
        struct.pack_into("<Q", p, 0x04, ft(when))
        struct.pack_into("<I", p, 0x10, parent & 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x14, subkeys)
        struct.pack_into("<I", p, 0x1C, sub_list & 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x24, values)
        struct.pack_into("<I", p, 0x28, val_list & 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x2C, 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x30, 0xFFFFFFFF)
        struct.pack_into("<H", p, 0x48, len(nm))
        p[0x4C:0x4C + len(nm)] = nm
        return self._alloc(bytes(p))

    def vk_sz(self, name, text):
        return self._vk(name, text.encode("utf-16-le") + b"\x00\x00", 1)

    def vk_dword(self, name, val):
        return self._vk(name, struct.pack("<I", val), 4)

    def _vk(self, name, data, dtype):
        nm = name.encode("latin-1")
        data_off = self._alloc(data)
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, len(data))
        struct.pack_into("<I", p, 0x08, data_off)
        struct.pack_into("<I", p, 0x0C, dtype)
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def li(self, entries):
        p = bytearray(4 + 4 * len(entries))
        p[0:2] = b"li"
        struct.pack_into("<H", p, 0x02, len(entries))
        for i, off in enumerate(entries):
            struct.pack_into("<I", p, 4 + i * 4, off)
        return self._alloc(bytes(p))

    def value_list(self, entries):
        return self._alloc(struct.pack(f"<{len(entries)}I", *entries))

    def build(self, root_offset):
        need = 0x20 + len(self.body)
        span = ((need + HBIN - 1) // HBIN) * HBIN
        hbin = bytearray(span)
        hbin[0:4] = b"hbin"
        struct.pack_into("<II", hbin, 4, 0, span)
        struct.pack_into("<Q", hbin, 20,
                         ft(datetime(2026, 1, 1, tzinfo=timezone.utc)))
        hbin[0x20:0x20 + len(self.body)] = bytes(self.body)
        used = 0x20 + len(self.body)
        if span - used >= 4:
            struct.pack_into("<i", hbin, used, span - used)
        base = bytearray(BASE)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 1)
        struct.pack_into("<Q", base, 0x0C,
                         ft(datetime(2026, 1, 1, tzinfo=timezone.utc)))
        struct.pack_into("<IIII", base, 0x14, 1, 3, 0, 1)
        struct.pack_into("<I", base, 0x24, root_offset)
        struct.pack_into("<I", base, 0x28, span)
        return bytes(base) + bytes(hbin)


def build_software_hive() -> bytes:
    b = HiveBuilder()
    when = datetime(2026, 3, 16, 9, 30, 0, tzinfo=timezone.utc)

    paths = b.nk("Paths", values=2, when=when, val_list=b.value_list([
        b.vk_dword("C:\\Users\\victim\\AppData\\Local\\Temp", 0),
        b.vk_dword("C:\\", 0)]))
    exts = b.nk("Extensions", values=1, when=when, val_list=b.value_list([
        b.vk_dword("ps1", 0)]))
    procs = b.nk("Processes", values=1, when=when, val_list=b.value_list([
        b.vk_dword("C:\\Windows\\System32\\powershell.exe", 0)]))
    excl = b.nk("Exclusions", subkeys=3,
                sub_list=b.li([paths, exts, procs]))

    rtp = b.nk("Real-Time Protection", values=2, when=when,
               val_list=b.value_list([
                   b.vk_dword("DisableRealtimeMonitoring", 1),
                   b.vk_dword("DisableBehaviorMonitoring", 1)]))
    features = b.nk("Features", values=1, when=when, val_list=b.value_list([
        b.vk_dword("TamperProtection", 0)]))
    defender = b.nk("Windows Defender", subkeys=3, values=1, when=when,
                    sub_list=b.li([excl, rtp, features]),
                    val_list=b.value_list([
                        b.vk_dword("DisableAntiSpyware", 1)]))
    ms = b.nk("Microsoft", subkeys=1, sub_list=b.li([defender]))
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=b.li([ms]))
    return b.build(root)
