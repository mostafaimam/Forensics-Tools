r"""cloud_dropbox - locate and generically inspect Dropbox sync-client
databases (``%LOCALAPPDATA%\Dropbox\instance*\`` / ``~/.dropbox/``).

Dropbox's ``config.dbx`` / ``filecache.dbx`` are a **proprietary,
undocumented** SQLite variant - and, in every Dropbox client released
in roughly the last decade, the file is SQLCipher-encrypted, keyed by
material this project has no confident, verified way to derive or
locate (it has varied by OS: DPAPI on Windows historically, the OS
keychain on macOS, a hardcoded/derived key on Linux, and Dropbox has
changed this scheme more than once). Rather than guess, v0.1 locates
candidate `.dbx` files, detects whether each one is plain SQLite (an
older client, or one whose encryption was disabled/not yet applied)
and generically dumps it table by table if so - full row fidelity, no
claimed understanding of the schema beyond conservative column-name
hints. An encrypted `.dbx` is reported as such, not decrypted.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
