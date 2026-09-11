"""Decode a 48-digit BitLocker recovery password and stretch it to a key.

The 48-digit recovery password (printed as 8 groups of 6 digits) encodes
8 little-endian 16-bit words: each group's integer value is a multiple of
11 (a checksum baked into the digit encoding); dividing by 11 recovers
the word.  The 16 resulting bytes are SHA-256 hashed once to seed the
"key stretching" loop - a fixed 0x100000-iteration chain of SHA-256 over
(last hash || salt || counter) - whose final output is the AES key used
to unwrap a VMK protector.
"""

from __future__ import annotations

import hashlib
import re
import struct

_GROUP = re.compile(r"^\d{6}$")
STRETCH_ITERATIONS = 0x100000


class RecoveryError(ValueError):
    pass


def parse_recovery_password(text: str) -> bytes:
    """Return the 16 raw bytes encoded by a 48-digit recovery password
    (accepts groups separated by '-', spaces, or given as one 48-digit
    string)."""
    groups = re.split(r"[\s-]+", text.strip())
    if len(groups) == 1 and len(groups[0]) == 48:
        groups = [groups[0][i:i + 6] for i in range(0, 48, 6)]
    if len(groups) != 8:
        raise RecoveryError("expected 8 groups of 6 digits (48 digits total)")
    out = bytearray()
    for g in groups:
        if not _GROUP.match(g):
            raise RecoveryError(f"bad group {g!r}: must be 6 digits")
        value = int(g)
        if value % 11 != 0:
            raise RecoveryError(f"bad group {g!r}: not a valid recovery "
                               f"password (checksum failed)")
        out += struct.pack("<H", value // 11)
    return bytes(out)


def stretch_key(password_bytes: bytes, salt: bytes, *,
                iterations: int = STRETCH_ITERATIONS) -> bytes:
    """The BitLocker key-stretching KDF: seed with SHA-256(password_bytes),
    then chain SHA-256(last_hash || salt || counter) `iterations` times."""
    last_hash = hashlib.sha256(password_bytes).digest()
    for counter in range(iterations):
        last_hash = hashlib.sha256(
            last_hash + salt + struct.pack("<Q", counter)).digest()
    return last_hash


def derive_key_from_recovery_password(text: str, salt: bytes, *,
                                      iterations: int = STRETCH_ITERATIONS
                                      ) -> bytes:
    return stretch_key(parse_recovery_password(text), salt,
                       iterations=iterations)
