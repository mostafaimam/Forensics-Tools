"""VeraCrypt / TrueCrypt volume header: salt + AES-XTS-encrypted fields.

Layout (this project's best-effort reading of the published VeraCrypt
Volume Format specification - see the package docstring for the
confidence caveat):

    offset   size  field
    0        64    salt (cleartext)
    64        4    magic: b"VERA" or b"TRUE"
    68        2    header format version (big-endian)
    70        2    minimum program version to open (big-endian)
    72       20    reserved (zero)
    92        8    hidden volume size, big-endian (0 for a standard volume)
    100       8    volume size, big-endian
    108       8    byte offset of the start of the master-key scope (BE)
    116       8    size of the encrypted (master-key-scope) area, BE
    124       4    flags, big-endian
    128       4    sector size, big-endian (0 in legacy TrueCrypt headers)
    132      120   reserved (zero)
    252       4    CRC-32 of decrypted bytes 64-251, big-endian
    256      256   master keydata (first 64 bytes used for AES-256-XTS:
                   32-byte primary/data key + 32-byte secondary/tweak key)

Bytes 64-511 (448 bytes) are one AES-XTS data unit, always decrypted
with data-unit index 0 regardless of where the header physically sits
in the container.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

from mounting_veracrypt import aes

_SALT_SIZE = 64
_HEADER_SIZE = 512
_ENC_SIZE = _HEADER_SIZE - _SALT_SIZE
_MAGICS = (b"VERA", b"TRUE")


class HeaderError(ValueError):
    pass


@dataclass
class Header:
    magic: bytes
    version: int
    min_version: int
    hidden_volume_size: int
    volume_size: int
    master_key_scope_offset: int
    encrypted_area_size: int
    flags: int
    sector_size: int
    primary_key: bytes
    tweak_key: bytes

    @property
    def is_hidden(self) -> bool:
        return self.hidden_volume_size != 0

    @property
    def effective_sector_size(self) -> int:
        return self.sector_size or 512


def derive_header_key(password: bytes, salt: bytes, *, hash_name: str = "sha512",
                      iterations: int = 500_000) -> bytes:
    if hash_name not in ("sha512", "sha256"):
        raise HeaderError(f"unsupported PBKDF2 hash {hash_name!r} "
                          f"(v0.1 supports sha512, sha256)")
    return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, 64)


def _try_decrypt(blob: bytes, header_key: bytes) -> Header | None:
    key1, key2 = header_key[:32], header_key[32:64]
    dec = aes.xts_decrypt_sector(key1, key2, 0, blob[_SALT_SIZE:])
    if dec[0:4] not in _MAGICS:
        return None
    crc_stored = struct.unpack(">I", dec[188:192])[0]
    crc_computed = zlib.crc32(dec[0:188]) & 0xFFFFFFFF
    if crc_stored != crc_computed:
        return None
    version, min_version = struct.unpack(">HH", dec[4:8])
    (hidden_size, vol_size, key_scope_off,
     enc_area_size) = struct.unpack(">QQQQ", dec[28:60])
    flags, sector_size = struct.unpack(">II", dec[60:68])
    keydata = dec[192:448]
    return Header(dec[0:4], version, min_version, hidden_size, vol_size,
                 key_scope_off, enc_area_size, flags, sector_size,
                 keydata[0:32], keydata[32:64])


def try_password(image_path: str, password: str, *, hash_name: str = "sha512",
                 iterations: int = 500_000) -> Header:
    """Try the primary header (offset 0) and the hidden-volume header slot
    (immediately after it, salt+encrypted region repeated) against a
    password. Raises HeaderError if neither decrypts."""
    with open(image_path, "rb") as fh:
        primary = fh.read(_HEADER_SIZE)
        hidden = fh.read(_HEADER_SIZE)
    if len(primary) < _HEADER_SIZE:
        raise HeaderError("file too short for a VeraCrypt header")
    key = derive_header_key(password.encode("utf-8"), primary[:_SALT_SIZE],
                            hash_name=hash_name, iterations=iterations)
    hdr = _try_decrypt(primary, key)
    if hdr is not None:
        return hdr
    if len(hidden) == _HEADER_SIZE:
        key2 = derive_header_key(password.encode("utf-8"),
                                 hidden[:_SALT_SIZE], hash_name=hash_name,
                                 iterations=iterations)
        hdr = _try_decrypt(hidden, key2)
        if hdr is not None:
            return hdr
    raise HeaderError("password did not decrypt the volume header "
                      "(wrong password, wrong --hash/--iterations, or an "
                      "unsupported cipher)")
