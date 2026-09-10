"""Hand-build a minimal ``regf`` hive with a TaskCache subtree.

A single oversized hive bin keeps the cell-offset maths trivial (the
reader treats offsets as a flat address space over the bins).
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 4096


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def filetime_blob(*dts) -> bytes:
    out = struct.pack("<I", 3)                    # version
    for dt in dts:
        out += struct.pack("<Q", ft(dt) if dt else 0)
    return out.ljust(0x20, b"\x00")


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

    def nk(self, name: str, *, parent: int = 0, flags: int = 0x20,
           subkeys: int = 0, sub_list: int = 0xFFFFFFFF,
           values: int = 0, val_list: int = 0xFFFFFFFF,
           when: datetime | None = None) -> int:
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

    def vk_sz(self, name: str, text: str) -> int:
        return self._vk(name, text.encode("utf-16-le") + b"\x00\x00", 1)

    def vk_bin(self, name: str, data: bytes) -> int:
        return self._vk(name, data, 3)

    def _vk(self, name: str, data: bytes, dtype: int) -> int:
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

    def li(self, entries: list[int]) -> int:
        p = bytearray(4 + 4 * len(entries))
        p[0:2] = b"li"
        struct.pack_into("<H", p, 0x02, len(entries))
        for i, off in enumerate(entries):
            struct.pack_into("<I", p, 4 + i * 4, off)
        return self._alloc(bytes(p))

    def value_list(self, entries: list[int]) -> int:
        return self._alloc(struct.pack(f"<{len(entries)}I", *entries))

    def build(self, root_offset: int) -> bytes:
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


G_EVIL = "{11111111-1111-1111-1111-111111111111}"
G_GOOD = "{22222222-2222-2222-2222-222222222222}"
G_HIDDEN = "{33333333-3333-3333-3333-333333333333}"
G_REGONLY = "{44444444-4444-4444-4444-444444444444}"


def build_software_hive() -> bytes:
    b = HiveBuilder()
    reg = datetime(2026, 2, 1, 3, 14, 0, tzinfo=timezone.utc)
    run = datetime(2026, 2, 10, 6, 0, 0, tzinfo=timezone.utc)

    # --- TaskCache\Tree ---
    evil_tree = b.nk("EvilPersist", val_list=b.value_list(
        [b.vk_sz("Id", G_EVIL)]), values=1)
    goodscan = b.nk("GoodScan", val_list=b.value_list(
        [b.vk_sz("Id", G_GOOD)]), values=1)
    defender = b.nk("Defender", subkeys=1, sub_list=b.li([goodscan]))
    windows_t = b.nk("Windows", subkeys=1, sub_list=b.li([defender]))
    ms_t = b.nk("Microsoft", subkeys=1, sub_list=b.li([windows_t]))
    tree = b.nk("Tree", subkeys=2, sub_list=b.li([evil_tree, ms_t]))

    # --- TaskCache\Tasks ---
    def task(guid, path, *, dyn=True):
        vals = [b.vk_sz("Path", path)]
        if dyn:
            vals.append(b.vk_bin("DynamicInfo", filetime_blob(reg, run)))
        vals.append(b.vk_bin("SD", b"\x01\x00\x04\x80" + b"\x00" * 20))
        return b.nk(guid, values=len(vals), val_list=b.value_list(vals))

    t_evil = task(G_EVIL, "\\EvilPersist")
    t_good = task(G_GOOD, "\\Microsoft\\Windows\\Defender\\GoodScan")
    t_hidden = task(G_HIDDEN, "\\HiddenBackdoor")          # not in Tree
    t_ro = task(G_REGONLY, "\\RegistryGhost")              # not in Tree, no XML
    tasks = b.nk("Tasks", subkeys=4,
                 sub_list=b.li([t_evil, t_good, t_hidden, t_ro]))

    taskcache = b.nk("TaskCache", subkeys=2, sub_list=b.li([tree, tasks]))
    schedule = b.nk("Schedule", subkeys=1, sub_list=b.li([taskcache]))
    cv = b.nk("CurrentVersion", subkeys=1, sub_list=b.li([schedule]))
    winnt = b.nk("Windows NT", subkeys=1, sub_list=b.li([cv]))
    ms = b.nk("Microsoft", subkeys=1, sub_list=b.li([winnt]))
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=b.li([ms]))
    return b.build(root)
