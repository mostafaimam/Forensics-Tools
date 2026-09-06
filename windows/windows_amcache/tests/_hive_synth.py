"""Hand-build a minimal but valid ``regf`` hive for the test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 65536


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


class HiveBuilder:
    def __init__(self) -> None:
        self.body = bytearray()      # cells, starting at hbin-relative 0x20
        self._cursor = 0x20

    def _alloc(self, payload: bytes, allocated: bool = True) -> int:
        size = 4 + len(payload)
        size = (size + 7) & ~7
        pad = size - 4 - len(payload)
        raw = struct.pack("<i", -size if allocated else size) + payload + b"\x00" * pad
        offset = self._cursor
        self.body += raw
        self._cursor += size
        return offset

    # -- cell builders ------------------------------------------
    def nk(self, name: str, *, parent: int, flags: int = 0x20,
           subkeys: int = 0, sub_list: int = 0xFFFFFFFF,
           values: int = 0, val_list: int = 0xFFFFFFFF,
           when: datetime | None = None, allocated: bool = True) -> int:
        when = when or datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
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
        struct.pack_into("<I", p, 0x2C, 0xFFFFFFFF)   # security
        struct.pack_into("<I", p, 0x30, 0xFFFFFFFF)   # class
        struct.pack_into("<H", p, 0x48, len(nm))
        p[0x4C:0x4C + len(nm)] = nm
        return self._alloc(bytes(p), allocated)

    def vk(self, name: str, data: bytes, data_type: int) -> int:
        nm = name.encode("latin-1")
        # store data in its own cell
        data_off = self._alloc(data)
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, len(data))
        struct.pack_into("<I", p, 0x08, data_off)
        struct.pack_into("<I", p, 0x0C, data_type)
        struct.pack_into("<H", p, 0x10, 0x0001)       # VALUE_COMP_NAME (ASCII)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def vk_resident_dword(self, name: str, value: int) -> int:
        nm = name.encode("latin-1")
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, 0x80000004)   # resident, 4 bytes
        struct.pack_into("<I", p, 0x08, value)
        struct.pack_into("<I", p, 0x0C, 4)            # REG_DWORD
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def lh(self, entries: list[int]) -> int:
        p = bytearray(4 + 8 * len(entries))
        p[0:2] = b"lh"
        struct.pack_into("<H", p, 0x02, len(entries))
        for i, off in enumerate(entries):
            struct.pack_into("<II", p, 4 + i * 8, off, 0)
        return self._alloc(bytes(p))

    def value_list(self, entries: list[int]) -> int:
        p = struct.pack(f"<{len(entries)}I", *entries)
        return self._alloc(p)

    # -- finalise ----------------------------------------------
    def build(self, root_offset: int) -> bytes:
        hbin = bytearray(HBIN)
        hbin[0:4] = b"hbin"
        struct.pack_into("<II", hbin, 4, 0, HBIN)
        struct.pack_into("<Q", hbin, 20, ft(datetime(2024, 5, 1, tzinfo=timezone.utc)))
        body = bytes(self.body)
        assert len(body) + 0x20 <= HBIN, "test hive body overflows one hbin"
        hbin[0x20:0x20 + len(body)] = body
        # remaining space: one big free cell
        used = 0x20 + len(body)
        struct.pack_into("<i", hbin, used, HBIN - used)

        base = bytearray(BASE)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 1)        # clean
        struct.pack_into("<Q", base, 0x0C, ft(datetime(2024, 5, 1, tzinfo=timezone.utc)))
        struct.pack_into("<IIII", base, 0x14, 1, 3, 0, 1)
        struct.pack_into("<I", base, 0x24, root_offset)
        struct.pack_into("<I", base, 0x28, HBIN)
        name = "\\??\\C:\\hive.dat".encode("utf-16-le")
        base[0x30:0x30 + len(name)] = name
        return bytes(base) + bytes(hbin)


def build_sample_hive() -> bytes:
    b = HiveBuilder()
    when_run = datetime(2024, 4, 2, 8, 30, 0, tzinfo=timezone.utc)

    # values for the Run key
    run_v = b.vk("OneDrive", "C:\\Users\\a\\OneDrive.exe".encode("utf-16-le")
                 + b"\x00\x00", 1)
    run_vl = b.value_list([run_v])
    run = b.nk("Run", parent=0, values=1, val_list=run_vl, when=when_run)
    run_list = b.lh([run])

    cv = b.nk("CurrentVersion", parent=0, subkeys=1, sub_list=run_list)
    cv_list = b.lh([cv])
    windows = b.nk("Windows", parent=0, subkeys=1, sub_list=cv_list)
    win_list = b.lh([windows])
    ms = b.nk("Microsoft", parent=0, subkeys=1, sub_list=win_list)
    ms_list = b.lh([ms])
    software = b.nk("Software", parent=0, subkeys=1, sub_list=ms_list)

    # a normal test key with a dword + string
    dv = b.vk_resident_dword("Count", 7)
    sv = b.vk("Note", "hello world".encode("utf-16-le") + b"\x00\x00", 1)
    tk_vl = b.value_list([dv, sv])
    testkey = b.nk("TestKey", parent=0, values=2, val_list=tk_vl,
                   when=datetime(2024, 3, 3, tzinfo=timezone.utc))

    sw_list = b.lh([software, testkey])
    root = b.nk("ROOT", parent=0, flags=0x2C, subkeys=2, sub_list=sw_list)

    # fixups: parent offsets left as 0 (not needed by the reader for the walk)
    # a DELETED orphan key in a free cell
    b.nk("DeletedSecretKey", parent=0, when=datetime(2024, 4, 9, tzinfo=timezone.utc),
         allocated=False)

    return b.build(root)
