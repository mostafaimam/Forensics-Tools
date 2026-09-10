"""Hand-build a minimal ``regf`` UsrClass.dat with a BagMRU shellbag tree."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 4096


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def _dosdate(dt: datetime) -> tuple[int, int]:
    d = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return d, t


# ---- shell items -------------------------------------------------------
def guid_item(guid: str) -> bytes:
    body = b"\x1f\x50" + uuid.UUID(guid).bytes_le
    return struct.pack("<H", len(body) + 2) + body


def drive_item(letter: str) -> bytes:
    body = b"\x2f" + letter.encode("latin-1") + b"\x00" * (22 - len(letter))
    return struct.pack("<H", len(body) + 2) + body


def dir_item(short: str, long: str, *, mft_entry=0, mft_seq=0,
             created=None, accessed=None, modified=None) -> bytes:
    modified = modified or datetime(2026, 2, 3, 9, 0, 0)
    created = created or datetime(2026, 2, 1, 8, 0, 0)
    accessed = accessed or datetime(2026, 2, 10, 7, 0, 0)
    md, mt = _dosdate(modified)
    b = bytearray()
    b += b"\x31"                                   # directory
    b += b"\x00"                                   # unknown
    b += struct.pack("<I", 0)                      # file size
    b += struct.pack("<HH", md, mt)                # mod date/time
    b += struct.pack("<H", 0x10)                   # attrs = FILE_ATTRIBUTE_DIR
    name = short.encode("latin-1") + b"\x00"
    b += name
    if len(b) % 2:
        b += b"\x00"

    # BEEF0004 extension block
    cd, ct = _dosdate(created)
    ad, at = _dosdate(accessed)
    ext = bytearray()
    ext += b"\x00\x00"                             # size placeholder
    ext += struct.pack("<H", 0x09)                 # version
    ext += struct.pack("<I", 0xBEEF0004)           # signature
    ext += struct.pack("<HH", cd, ct)             # created
    ext += struct.pack("<HH", ad, at)             # accessed
    ext += struct.pack("<H", 0x14)                # unknown (attrs)
    ext += struct.pack("<H", 0)                   # unknown
    ext += struct.pack("<Q", (mft_seq << 48) | (mft_entry & 0xFFFFFFFFFFFF))
    ext += struct.pack("<Q", 0)                   # unknown
    ext += struct.pack("<I", 0)                   # long-string size
    ext += long.encode("utf-16-le") + b"\x00\x00"
    if len(ext) % 2:
        ext += b"\x00"
    ext += struct.pack("<H", len(b))             # offset back to first ext
    struct.pack_into("<H", ext, 0, len(ext))
    b += ext

    return struct.pack("<H", len(b) + 2) + bytes(b)


def network_item(unc: str) -> bytes:
    body = b"\xc3\x01\x00\x00\x00" + unc.encode("latin-1") + b"\x00"
    return struct.pack("<H", len(body) + 2) + body


def mrulistex(order: list[int]) -> bytes:
    return b"".join(struct.pack("<i", n) for n in order) + b"\xff\xff\xff\xff"


# ---- hive builder ----------------------------------------------------
class HiveBuilder:
    def __init__(self) -> None:
        self.body = bytearray()
        self._cursor = 0x20

    def _alloc(self, payload: bytes) -> int:
        size = (4 + len(payload) + 7) & ~7
        pad = size - 4 - len(payload)
        self.body += struct.pack("<i", -size) + payload + b"\x00" * pad
        off = self._cursor
        self._cursor += size
        return off

    def nk(self, name, *, subkeys=0, sub_list=0xFFFFFFFF, values=0,
           val_list=0xFFFFFFFF, when=None, flags=0x20):
        when = when or datetime(2026, 2, 3, 9, 0, tzinfo=timezone.utc)
        nm = name.encode("latin-1")
        p = bytearray(0x4C + len(nm))
        p[0:2] = b"nk"
        struct.pack_into("<H", p, 0x02, flags)
        struct.pack_into("<Q", p, 0x04, ft(when))
        struct.pack_into("<I", p, 0x14, subkeys)
        struct.pack_into("<I", p, 0x1C, sub_list & 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x24, values)
        struct.pack_into("<I", p, 0x28, val_list & 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x2C, 0xFFFFFFFF)
        struct.pack_into("<I", p, 0x30, 0xFFFFFFFF)
        struct.pack_into("<H", p, 0x48, len(nm))
        p[0x4C:] = nm
        return self._alloc(bytes(p))

    def vk(self, name, data, dtype):
        nm = name.encode("latin-1")
        data_off = self._alloc(data)
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, len(data))
        struct.pack_into("<I", p, 0x08, data_off)
        struct.pack_into("<I", p, 0x0C, dtype)
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:] = nm
        return self._alloc(bytes(p))

    def vk_dword(self, name, value):
        nm = name.encode("latin-1")
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, 0x80000004)
        struct.pack_into("<I", p, 0x08, value)
        struct.pack_into("<I", p, 0x0C, 4)
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:] = nm
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
                         ft(datetime(2026, 2, 3, tzinfo=timezone.utc)))
        hbin[0x20:0x20 + len(self.body)] = bytes(self.body)
        used = 0x20 + len(self.body)
        if span - used >= 4:
            struct.pack_into("<i", hbin, used, span - used)
        base = bytearray(BASE)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 1)
        struct.pack_into("<Q", base, 0x0C,
                         ft(datetime(2026, 2, 3, tzinfo=timezone.utc)))
        struct.pack_into("<IIII", base, 0x14, 1, 3, 0, 1)
        struct.pack_into("<I", base, 0x24, root_offset)
        struct.pack_into("<I", base, 0x28, span)
        return bytes(base) + bytes(hbin)


THIS_PC = "20d04fe0-3aea-1069-a2d8-08002b30309d"


def build_usrclass() -> bytes:
    b = HiveBuilder()
    t = lambda *a: datetime(*a, tzinfo=timezone.utc)  # noqa: E731

    # deepest first: C:\Users\attacker\Downloads\tools
    tools = b.nk("0", when=t(2026, 2, 12, 11, 0),
                 val_list=b.value_list([
                     b.vk("MRUListEx", mrulistex([0]), 3),
                     b.vk("NodeSlot", struct.pack("<I", 12), 4)]), values=2)
    # Downloads level: value 0 = "tools" dir, subkey 0 recurses
    downloads = b.nk("0", when=t(2026, 2, 12, 10, 30), subkeys=1,
                     sub_list=b.li([tools]),
                     val_list=b.value_list([
                         b.vk("0", dir_item("tools", "tools",
                                            mft_entry=51201, mft_seq=4,
                                            created=t(2026, 2, 11)), 3),
                         b.vk("MRUListEx", mrulistex([0]), 3),
                         b.vk("NodeSlot", struct.pack("<I", 11), 4)]),
                     values=3)
    # attacker profile: value 0 = "Downloads"
    attacker = b.nk("1", when=t(2026, 2, 12, 10, 0), subkeys=1,
                    sub_list=b.li([downloads]),
                    val_list=b.value_list([
                        b.vk("0", dir_item("Downloads", "Downloads",
                                           mft_entry=4501, mft_seq=2), 3),
                        b.vk("MRUListEx", mrulistex([0]), 3),
                        b.vk("NodeSlot", struct.pack("<I", 10), 4)]),
                    values=3)
    # a network share child of "This PC"
    netshare = b.nk("2", when=t(2026, 2, 9, 14, 0),
                    val_list=b.value_list([
                        b.vk("MRUListEx", mrulistex([]), 3),
                        b.vk("NodeSlot", struct.pack("<I", 9), 4)]), values=2)
    # Users dir (child 0 of C:) -> holds "attacker" (child 1) and a zip
    zipkid = b.nk("0", when=t(2026, 2, 8, 16, 0),
                  val_list=b.value_list([
                      b.vk("MRUListEx", mrulistex([]), 3)]), values=1)
    users = b.nk("0", when=t(2026, 2, 12, 10, 0), subkeys=2,
                 sub_list=b.li([zipkid, attacker]),
                 val_list=b.value_list([
                     b.vk("0", dir_item("report.zip", "report.zip"), 3),
                     b.vk("1", dir_item("attacker", "attacker",
                                        mft_entry=1337, mft_seq=1), 3),
                     b.vk("MRUListEx", mrulistex([1, 0]), 3),
                     b.vk("NodeSlot", struct.pack("<I", 4), 4)]),
                 values=4)
    # C: drive (child 0 of This PC)
    cdrive = b.nk("0", when=t(2026, 2, 12, 10, 0), subkeys=1,
                  sub_list=b.li([users]),
                  val_list=b.value_list([
                      b.vk("0", dir_item("Users", "Users",
                                         mft_entry=1200, mft_seq=1), 3),
                      b.vk("MRUListEx", mrulistex([0]), 3),
                      b.vk("NodeSlot", struct.pack("<I", 3), 4)]),
                  values=3)
    # BagMRU root
    bagmru = b.nk("BagMRU", when=t(2026, 2, 12, 12, 0), subkeys=2,
                  sub_list=b.li([cdrive, netshare]),
                  val_list=b.value_list([
                      b.vk("0", drive_item("C:\\"), 3),
                      b.vk("2", network_item("\\\\FILESRV\\backup"), 3),
                      b.vk("MRUListEx", mrulistex([0, 2]), 3),
                      b.vk("NodeSlot", struct.pack("<I", 1), 4)]),
                  values=4)

    shell = b.nk("Shell", subkeys=1, sub_list=b.li([bagmru]))
    win = b.nk("Windows", subkeys=1, sub_list=b.li([shell]))
    ms = b.nk("Microsoft", subkeys=1, sub_list=b.li([win]))
    sw = b.nk("Software", subkeys=1, sub_list=b.li([ms]))
    ls = b.nk("Local Settings", subkeys=1, sub_list=b.li([sw]))
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=b.li([ls]))
    return b.build(root)
