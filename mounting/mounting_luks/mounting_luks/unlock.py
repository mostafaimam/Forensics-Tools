"""Try a passphrase against a LUKS1 header's active key slots."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from mounting_luks.af import af_merge
from mounting_luks.essiv import cbc_essiv_decrypt
from mounting_luks.luks1 import Luks1Header

_SECTOR = 512


class UnlockError(ValueError):
    pass


@dataclass
class Unlocked:
    master_key: bytes
    slot_index: int


def _essiv_hash(cipher_mode: str) -> str:
    if not cipher_mode.startswith("cbc-essiv:"):
        raise UnlockError(f"unsupported cipher mode {cipher_mode!r} "
                          f"(only cbc-essiv:<hash> in v0.1)")
    return cipher_mode.split(":", 1)[1]


def unlock(header: Luks1Header, image_path: str, passphrase: str) -> Unlocked:
    essiv_hash = _essiv_hash(header.cipher_mode)
    pw = passphrase.encode("utf-8")
    with open(image_path, "rb") as fh:
        last_err = None
        for slot in header.slots:
            if not slot.active:
                continue
            try:
                slot_key = hashlib.pbkdf2_hmac(
                    header.hash_spec, pw, slot.salt, slot.iterations,
                    header.key_bytes)
                material_len = slot.stripes * header.key_bytes
                fh.seek(slot.key_material_offset * _SECTOR)
                material = fh.read(material_len)
                if len(material) != material_len:
                    last_err = f"slot {slot.index}: truncated key material"
                    continue
                split = cbc_essiv_decrypt(slot_key, essiv_hash, material,
                                          slot.key_material_offset)
                candidate = af_merge(split, slot.stripes, header.key_bytes)
                digest = hashlib.pbkdf2_hmac(
                    header.hash_spec, candidate, header.mk_digest_salt,
                    header.mk_digest_iterations, len(header.mk_digest))
                if digest == header.mk_digest:
                    return Unlocked(master_key=candidate,
                                    slot_index=slot.index)
                last_err = f"slot {slot.index}: digest mismatch"
            except Exception as e:  # noqa: BLE001
                last_err = f"slot {slot.index}: {e}"
    raise UnlockError(f"passphrase did not unlock any active key slot: "
                      f"{last_err}")
