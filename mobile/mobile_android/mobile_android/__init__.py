r"""mobile_android - read an `adb backup` (.ab) archive.

An .ab file is a small ASCII text header (magic, format version,
compression flag, encryption algorithm - and, if encrypted, PBKDF2/AES
key-wrapping parameters) followed by the payload: optionally
zlib-compressed, optionally AES-256-CBC-encrypted, and underneath that
always a plain POSIX tar stream of the backed-up app data (``apps/
<package>/f/...`` for files, ``.../db/...`` for databases, ``.../sp/...``
for shared preferences, plus ``shared/...`` for external/shared storage
if included). This format has been reverse-engineered and cross
-validated by community tools for well over a decade - high confidence.

v0.1 handles **unencrypted backups only** (``encryption: none``, the
common case for a backup taken with no password set on the device
prompt): the header parse and any zlib decompression are exact, and
the tar payload is read with the standard library's own ``tarfile``
module rather than a hand-rolled reader. An encrypted backup is
detected and reported, not decrypted - see the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
