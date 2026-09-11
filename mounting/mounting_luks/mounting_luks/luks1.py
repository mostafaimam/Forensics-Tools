"""Parse a LUKS1 header (and detect LUKS2, reported but not unlockable)."""

from __future__ import annotations

import struct
import uuid as _uuid
from dataclasses import dataclass, field

_MAGIC = b"LUKS\xba\xbe"
ACTIVE = 0x00AC71F3
INACTIVE = 0x0000DEAD
HEADER_SIZE = 0x250
_SECTOR = 512


class LuksError(ValueError):
    pass


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", "replace")


@dataclass
class KeySlot:
    index: int
    active: bool
    iterations: int
    salt: bytes
    key_material_offset: int      # in 512-byte sectors
    stripes: int


@dataclass
class Luks1Header:
    version: int
    cipher_name: str
    cipher_mode: str
    hash_spec: str
    payload_offset: int            # sectors
    key_bytes: int
    mk_digest: bytes
    mk_digest_salt: bytes
    mk_digest_iterations: int
    uuid: str
    slots: list = field(default_factory=list)

    @property
    def payload_byte_offset(self) -> int:
        return self.payload_offset * _SECTOR


def parse(data: bytes) -> Luks1Header:
    if len(data) < HEADER_SIZE:
        raise LuksError("file too small for a LUKS header")
    if data[0:6] != _MAGIC:
        raise LuksError("missing LUKS magic (not a LUKS volume)")
    version = struct.unpack_from(">H", data, 6)[0]
    if version == 2:
        raise LuksError("LUKS2 header detected - use luks2_info() for the "
                        "JSON metadata; unlocking needs Argon2 (not "
                        "implemented in v0.1)")
    if version != 1:
        raise LuksError(f"unsupported LUKS version {version}")

    cipher_name = _cstr(data[0x08:0x28])
    cipher_mode = _cstr(data[0x28:0x48])
    hash_spec = _cstr(data[0x48:0x68])
    payload_offset = struct.unpack_from(">I", data, 0x68)[0]
    key_bytes = struct.unpack_from(">I", data, 0x6C)[0]
    mk_digest = data[0x70:0x84]
    mk_digest_salt = data[0x84:0xA4]
    mk_digest_iter = struct.unpack_from(">I", data, 0xA4)[0]
    uuid_str = _cstr(data[0xA8:0xD0])

    hdr = Luks1Header(version=version, cipher_name=cipher_name,
                      cipher_mode=cipher_mode, hash_spec=hash_spec,
                      payload_offset=payload_offset, key_bytes=key_bytes,
                      mk_digest=mk_digest[:20],
                      mk_digest_salt=mk_digest_salt[:32],
                      mk_digest_iterations=mk_digest_iter, uuid=uuid_str)
    for i in range(8):
        off = 0xD0 + i * 48
        active, iters = struct.unpack_from(">II", data, off)
        salt = data[off + 8:off + 40]
        km_off, stripes = struct.unpack_from(">II", data, off + 40)
        hdr.slots.append(KeySlot(index=i, active=(active == ACTIVE),
                                 iterations=iters, salt=salt,
                                 key_material_offset=km_off,
                                 stripes=stripes))
    return hdr


def luks2_info(data: bytes) -> dict:
    """Best-effort: report what a LUKS2 header claims, without unlocking."""
    if data[0:6] != _MAGIC:
        raise LuksError("missing LUKS magic")
    version = struct.unpack_from(">H", data, 6)[0]
    if version != 2:
        raise LuksError("not a LUKS2 header")
    uuid_str = _cstr(data[0xA8:0xD0]) if len(data) >= 0xD0 else ""
    return {"version": 2, "uuid": uuid_str,
           "note": "LUKS2 metadata is JSON at sector 4KiB+; KDF is "
                   "typically Argon2id, not implemented in v0.1"}
