r"""mounting_veracrypt - unlock a VeraCrypt/TrueCrypt volume with a
supplied password: PBKDF2 header-key derivation, AES-XTS header
decryption and validation, master-key extraction, sector decryption.
Bundled AES; the examiner supplies the password, nothing is brute
forced.

VeraCrypt's Volume Format is publicly specified, unlike BitLocker's FVE
metadata (reverse-engineered, not published by Microsoft). This
implementation follows this project's best-effort reading of that
specification: the 64-byte salt, the AES-XTS-encrypted 448-byte
header region (always data-unit 0 regardless of where the header sits
on disk), the ``VERA``/``TRUE`` magic + header CRC-32 as the password
-verification mechanism, and the master keydata region. It has **not**
been byte-verified against a real VeraCrypt-created volume in this
environment - see the README for exactly which fields carry lower
confidence than the magic/CRC check and master-key extraction.

v0.1 scope: password-only (no PIM, no keyfiles), PBKDF2-HMAC-SHA512/
SHA256 only, single-cipher AES-256-XTS volumes only (no Serpent/Twofish/
cascades, no legacy TrueCrypt RIPEMD160/non-XTS modes).
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
