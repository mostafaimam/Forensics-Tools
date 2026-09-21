r"""mobile_iosbackup - iTunes / Finder logical iOS backup reader.

A modern (iOS 10+) local iOS backup is a folder named after the
device's UDID containing ``Manifest.db`` (a SQLite index: one row per
backed-up file, keyed by ``fileID`` = ``sha1(domain + "-" +
relativePath)``), ``Manifest.plist`` (backup-level metadata, including
whether the backup is password-encrypted), ``Info.plist`` (device
identity), and the file contents themselves stored flat as
``<fileID[:2]>/<fileID>`` under the backup root.

Read-only, and **v0.1 handles unencrypted backups only**: an encrypted
backup's `Manifest.db` and file contents are themselves AES-encrypted
under a per-backup keybag unlocked from the backup password, using the
same class of undocumented, only-reverse-engineered keybag mechanism as
the APFS volume-encryption keybag - genuinely uncertain enough that this
project reports an encrypted backup as such rather than guessing at
unlocking it. Detecting/reporting encryption is in scope; decrypting an
iOS backup keybag is not (see the README).
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
