"""Hand-build minimal but valid SYSTEM and SAM regf hives for tests.

Adapted from windows_registry's hive-builder test fixture, extended
with key "class"-string support (the LSA boot-key permutation is
smuggled into that field).
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone

from memory_hashdump import des, rc4
from memory_hashdump.ridkey import deskeys_from_rid

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 4096

_PERMUTE = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
           0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]
_AQWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
_ANUM = b"0123456789012345678901234567890123456789\x00"
_LMPASSWORD = b"LMPASSWORD\x00"
_NTPASSWORD = b"NTPASSWORD\x00"


def bootkey_to_class_hex(bootkey: bytes) -> str:
    """Inverse of the LSA permutation: build the 'scrambled' class-name
    hex string that derive_bootkey() would turn back into `bootkey`."""
    scrambled = bytearray(16)
    for i, p in enumerate(_PERMUTE):
        scrambled[p] = bootkey[i]
    return bytes(scrambled).hex().upper()


def build_f_value_legacy(bootkey: bytes, hashedbootkey: bytes,
                         salt: bytes) -> bytes:
    rc4_key = hashlib.md5(salt + _AQWERTY + bootkey + _ANUM).digest()
    encrypted = rc4.crypt(rc4_key, hashedbootkey)
    f = bytearray(0x90)
    struct.pack_into("<L", f, 0, 2)
    f[0x70:0x80] = salt
    f[0x80:0x90] = encrypted
    return bytes(f)


def _encrypt_hash_legacy(plain16: bytes, rid: int, hbk: bytes, *,
                         is_nt: bool) -> bytes:
    const = _NTPASSWORD if is_nt else _LMPASSWORD
    rc4_key = hashlib.md5(hbk + struct.pack("<L", rid) + const).digest()
    k1, k2 = deskeys_from_rid(rid)
    obfuscated = des.encrypt_block(k1, plain16[:8]) + \
        des.encrypt_block(k2, plain16[8:16])
    return rc4.crypt(rc4_key, obfuscated)


def _hash_blob_legacy(encrypted16: bytes) -> bytes:
    return struct.pack("<HH", 1, 1) + encrypted16


def build_v_value(rid: int, hbk: bytes, *, lm: bytes | None,
                  nt: bytes | None) -> bytes:
    v = bytearray(0x100)
    if lm is not None:
        enc = _encrypt_hash_legacy(lm, rid, hbk, is_nt=False)
        v[0xCC:0xCC + 20] = _hash_blob_legacy(enc)
        struct.pack_into("<III", v, 0x9C, 0, 20, 0)
    if nt is not None:
        enc = _encrypt_hash_legacy(nt, rid, hbk, is_nt=True)
        v[0xE0:0xE0 + 20] = _hash_blob_legacy(enc)
        struct.pack_into("<III", v, 0xA8, 20, 20, 0)
    return bytes(v)


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


class HiveBuilder:
    def __init__(self) -> None:
        self.body = bytearray()
        self._cursor = 0x20

    def _alloc(self, payload: bytes, allocated: bool = True) -> int:
        size = 4 + len(payload)
        size = (size + 7) & ~7
        pad = size - 4 - len(payload)
        raw = struct.pack("<i", -size if allocated else size) + payload + \
            b"\x00" * pad
        offset = self._cursor
        self.body += raw
        self._cursor += size
        return offset

    def raw_data(self, data: bytes) -> int:
        return self._alloc(data)

    def nk(self, name: str, *, parent: int = 0, flags: int = 0x20,
          subkeys: int = 0, sub_list: int = 0xFFFFFFFF,
          values: int = 0, val_list: int = 0xFFFFFFFF,
          when: datetime | None = None, allocated: bool = True,
          klass: str | None = None) -> int:
        when = when or datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
        nm = name.encode("latin-1")
        class_offset = 0xFFFFFFFF
        class_length = 0
        if klass is not None:
            class_bytes = klass.encode("utf-16-le")
            class_offset = self._alloc(class_bytes)
            class_length = len(class_bytes)
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
        struct.pack_into("<I", p, 0x30, class_offset)
        struct.pack_into("<H", p, 0x48, len(nm))
        struct.pack_into("<H", p, 0x4A, class_length)
        p[0x4C:0x4C + len(nm)] = nm
        return self._alloc(bytes(p), allocated)

    def vk(self, name: str, data: bytes, data_type: int) -> int:
        nm = name.encode("latin-1")
        data_off = self._alloc(data)
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, len(data))
        struct.pack_into("<I", p, 0x08, data_off)
        struct.pack_into("<I", p, 0x0C, data_type)
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def vk_resident_dword(self, name: str, value: int) -> int:
        nm = name.encode("latin-1")
        p = bytearray(0x14 + len(nm))
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, len(nm))
        struct.pack_into("<I", p, 0x04, 0x80000004)
        struct.pack_into("<I", p, 0x08, value)
        struct.pack_into("<I", p, 0x0C, 4)
        struct.pack_into("<H", p, 0x10, 0x0001)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def vk_typed_marker(self, rid: int) -> int:
        """A zero-length value whose declared type IS the RID - the
        Users\\Names\\<username> trick."""
        p = bytearray(0x14)
        p[0:2] = b"vk"
        struct.pack_into("<H", p, 0x02, 0)
        struct.pack_into("<I", p, 0x04, 0x80000000)
        struct.pack_into("<I", p, 0x08, 0)
        struct.pack_into("<I", p, 0x0C, rid)
        struct.pack_into("<H", p, 0x10, 0x0000)
        return self._alloc(bytes(p))

    def lh(self, entries: list[int]) -> int:
        p = bytearray(4 + 8 * len(entries))
        p[0:2] = b"lh"
        struct.pack_into("<H", p, 0x02, len(entries))
        for i, off in enumerate(entries):
            struct.pack_into("<II", p, 4 + i * 8, off, 0)
        return self._alloc(bytes(p))

    def value_list(self, entries: list[int]) -> int:
        p = struct.pack(f"<{len(entries)}I", *entries) if entries else b""
        return self._alloc(p)

    def build(self, root_offset: int) -> bytes:
        hbin = bytearray(HBIN)
        hbin[0:4] = b"hbin"
        struct.pack_into("<II", hbin, 4, 0, HBIN)
        struct.pack_into("<Q", hbin, 20,
                         ft(datetime(2024, 5, 1, tzinfo=timezone.utc)))
        body = bytes(self.body)
        assert len(body) + 0x20 <= HBIN, "test hive body overflows one hbin"
        hbin[0x20:0x20 + len(body)] = body
        used = 0x20 + len(body)
        struct.pack_into("<i", hbin, used, HBIN - used)

        base = bytearray(BASE)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 1)
        struct.pack_into("<Q", base, 0x0C,
                         ft(datetime(2024, 5, 1, tzinfo=timezone.utc)))
        struct.pack_into("<IIII", base, 0x14, 1, 3, 0, 1)
        struct.pack_into("<I", base, 0x24, root_offset)
        struct.pack_into("<I", base, 0x28, HBIN)
        name = "\\??\\C:\\hive.dat".encode("utf-16-le")
        base[0x30:0x30 + len(name)] = name
        return bytes(base) + bytes(hbin)


def build_system_hive(class_hex: str) -> bytes:
    """class_hex: 32 hex chars split 8/8/8/8 across JD/Skew1/GBG/Data."""
    b = HiveBuilder()
    parts = [class_hex[i:i + 8] for i in range(0, 32, 8)]

    jd = b.nk("JD", klass=parts[0])
    skew1 = b.nk("Skew1", klass=parts[1])
    gbg = b.nk("GBG", klass=parts[2])
    data = b.nk("Data", klass=parts[3])
    lsa_list = b.lh([jd, skew1, gbg, data])
    lsa = b.nk("Lsa", subkeys=4, sub_list=lsa_list)
    control_list = b.lh([lsa])
    control = b.nk("Control", subkeys=1, sub_list=control_list)
    cs_list = b.lh([control])
    cs1 = b.nk("ControlSet001", subkeys=1, sub_list=cs_list)

    current_v = b.vk_resident_dword("Current", 1)
    current_vl = b.value_list([current_v])
    select = b.nk("Select", values=1, val_list=current_vl)

    root_list = b.lh([cs1, select])
    root = b.nk("ROOT", flags=0x2C, subkeys=2, sub_list=root_list)
    return b.build(root)


def build_sam_hive(f_value: bytes, users: list[tuple[int, str, bytes]]
                   ) -> bytes:
    """users: [(rid, username, v_value), ...]"""
    b = HiveBuilder()

    name_keys = []
    for rid, username, _v in users:
        marker = b.vk_typed_marker(rid)
        vl = b.value_list([marker])
        name_keys.append(b.nk(username, values=1, val_list=vl))
    names_list = b.lh(name_keys) if name_keys else 0xFFFFFFFF
    names_key = b.nk("Names", subkeys=len(name_keys), sub_list=names_list)

    rid_keys = []
    for rid, _username, v_value in users:
        vv = b.vk("V", v_value, 3)
        vl = b.value_list([vv])
        rid_keys.append(b.nk(f"{rid:08X}", values=1, val_list=vl))

    users_children = rid_keys + [names_key]
    users_list = b.lh(users_children)
    users_key = b.nk("Users", subkeys=len(users_children),
                     sub_list=users_list)

    f_v = b.vk("F", f_value, 3)
    account_vl = b.value_list([f_v])
    account = b.nk("Account", subkeys=1, sub_list=b.lh([users_key]),
                   values=1, val_list=account_vl)
    domains_list = b.lh([account])
    domains = b.nk("Domains", subkeys=1, sub_list=domains_list)
    root_list = b.lh([domains])
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=root_list)
    return b.build(root)
