r"""mounting_fvde - best-effort FileVault2/CoreStorage volume unlock.

**Confidence split, deliberately.** The cryptographic primitives here
are NIST/IETF standard and exact: PBKDF2-HMAC-SHA256 (stdlib
``hashlib``), RFC 3394 AES Key Unwrap (`keywrap.py`), and AES-XTS-128
sector decryption (`aes.py`, the same from-scratch, FIPS/standard
-verified core `mounting_veracrypt` and `mounting_luks` use). None of
that is a guess.

What genuinely **is** a guess: the exact byte-level layout of Apple's
CoreStorage ``EncryptedRoot.plist.wipekey`` - which fields inside a
found property-list blob are the PBKDF2 salt, the iteration count, and
the RFC-3394-wrapped key material. That inner layout is only known
through community reverse-engineering (the libfvde project), has never
been independently verified here against a real macOS-generated
volume, and this project has no confident recollection of its exact
byte offsets. Rather than silently guess and risk deriving a
plausible-looking but wrong key, `mounting_fvde`'s `info` command
surfaces every *candidate* blob it finds (path, length, hex) for the
examiner to judge, and `unlock`/`decrypt` take the salt, iteration
count, and wrapped-key bytes as **explicit, examiner-supplied
parameters** rather than auto-slicing them - the same "verify, don't
silently trust" posture `mounting_luks` uses for its master-key digest
check, applied here because the surrounding format itself is uncertain
in a way LUKS's published spec is not. A decrypted result is only
reported as a real unlock when it produces the expected HFS+/
CoreStorage container magic - never presented as valid without that
check passing.

APFS-container FileVault (as opposed to legacy CoreStorage) is out of
scope for v0.1 - it is a materially different keybag format this
project has even less confidence reconstructing correctly. See the
README's Confidence & Validation section before relying on this tool's
output as anything beyond an investigative lead.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
