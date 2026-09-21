"""Hand-build minimal but valid SYSTEM and SECURITY regf hives for tests.

Shares the generic hive-cell-builder mechanics with memory_hashdump's
test fixture (class-string support for the LSA boot-key permutation).
"""

from __future__ import annotations

import os
import struct
from datetime import datetime, timezone

from memory_lsasecrets import aes

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BASE = 4096
HBIN = 4096

_PERMUTE = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
           0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def bootkey_to_class_hex(bootkey: bytes) -> str:
    scrambled = bytearray(16)
    for i, p in enumerate(_PERMUTE):
        scrambled[p] = bootkey[i]
    return bytes(scrambled).hex().upper()


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
        struct.pack_into("<H", p, 0x10, 0x0001 if nm else 0x0000)
        p[0x14:0x14 + len(nm)] = nm
        return self._alloc(bytes(p))

    def vk_default(self, data: bytes, data_type: int = 3) -> int:
        return self.vk("", data, data_type)

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


def _lsa_secret_blob(key16: bytes, secret: bytes, salt: bytes) -> bytes:
    inner = struct.pack("<L", len(secret)) + b"\x00" * 12 + secret
    pad = (-len(inner)) % 16
    inner += b"\x00" * pad
    ciphertext = aes.encrypt_cbc(key16, salt, inner)
    return (struct.pack("<L", 1) + os.urandom(16) + struct.pack("<LL", 0, 0)
           + salt + ciphertext)


def build_polek_list_blob(bootkey: bytes, lsa_key: bytes) -> bytes:
    inner_payload = bytearray(68)
    inner_payload[36:68] = lsa_key
    return _lsa_secret_blob(bootkey[:16], bytes(inner_payload),
                            os.urandom(16))


def build_secret_blob(lsa_key: bytes, plaintext: bytes) -> bytes:
    return _lsa_secret_blob(lsa_key[:16], plaintext, os.urandom(16))


def build_security_hive(polek_list: bytes,
                        secrets: list[tuple[str, bytes]]) -> bytes:
    b = HiveBuilder()

    secret_name_keys = []
    for name, curr_val_blob in secrets:
        v = b.vk_default(curr_val_blob)
        vl = b.value_list([v])
        currval_key = b.nk("CurrVal", values=1, val_list=vl)
        cv_list = b.lh([currval_key])
        secret_name_keys.append(b.nk(name, subkeys=1, sub_list=cv_list))
    secrets_list = b.lh(secret_name_keys) if secret_name_keys else 0xFFFFFFFF
    secrets_key = b.nk("Secrets", subkeys=len(secret_name_keys),
                       sub_list=secrets_list)

    polek_v = b.vk_default(polek_list)
    polek_vl = b.value_list([polek_v])
    polek_key = b.nk("PolEKList", values=1, val_list=polek_vl)

    policy_children = [secrets_key, polek_key]
    policy_list = b.lh(policy_children)
    policy = b.nk("Policy", subkeys=len(policy_children),
                 sub_list=policy_list)
    root_list = b.lh([policy])
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=root_list)
    return b.build(root)
