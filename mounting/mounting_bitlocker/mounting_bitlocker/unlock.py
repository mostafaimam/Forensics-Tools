"""Unlock a BitLocker volume given a recovery password: VMK -> FVEK."""

from __future__ import annotations

from dataclasses import dataclass

from mounting_bitlocker import ccm
from mounting_bitlocker.fve import METHODS, FveError, FveMetadata
from mounting_bitlocker.recovery import (STRETCH_ITERATIONS,
                                         derive_key_from_recovery_password)


class UnlockError(ValueError):
    pass


@dataclass
class Unlocked:
    vmk: bytes
    fvek: bytes
    key1: bytes
    key2: bytes
    method: str
    protector_guid: str


def unlock_with_recovery_password(fve: FveMetadata, password: str, *,
                                  iterations: int = STRETCH_ITERATIONS
                                  ) -> Unlocked:
    recovery_protectors = [p for p in fve.protectors
                           if p.protector_type == "recovery password"
                           and p.salt and p.wrapped_key]
    if not recovery_protectors:
        raise UnlockError("no recovery-password protector with a stretch "
                          "salt and wrapped key in this metadata")

    last_err = None
    for prot in recovery_protectors:
        try:
            interm = derive_key_from_recovery_password(
                password, prot.salt, iterations=iterations)
            vmk = ccm.decrypt_and_verify(interm, prot.nonce, prot.wrapped_key)
        except (ccm.CcmError, Exception) as e:  # noqa: BLE001
            last_err = e
            continue
        if not fve.fvek_wrapped:
            raise UnlockError("VMK unlocked, but no FVEK dataset entry "
                              "was found in this metadata")
        try:
            fvek_blob = ccm.decrypt_and_verify(vmk, fve.fvek_nonce,
                                               fve.fvek_wrapped)
        except ccm.CcmError as e:
            raise UnlockError(f"VMK unlocked but FVEK unwrap failed: {e}")
        _name, keylen = METHODS.get(_method_code(fve.method), (fve.method,
                                                                32))
        if "xts" in fve.method:
            key1, key2 = fvek_blob[:keylen], fvek_blob[keylen:keylen * 2]
        else:
            key1, key2 = fvek_blob[:keylen], b""
        return Unlocked(vmk=vmk, fvek=fvek_blob, key1=key1, key2=key2,
                        method=fve.method, protector_guid=prot.guid)
    raise UnlockError(f"recovery password did not unlock any protector "
                      f"(wrong password?): {last_err}")


def _method_code(name: str) -> int:
    for code, (n, _l) in METHODS.items():
        if n == name:
            return code
    return -1
