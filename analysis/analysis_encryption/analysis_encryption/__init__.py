"""analysis_encryption - detect encrypted / password-protected files.

Signature and structural checks for the common schemes (Office, PDF, ZIP,
RAR, 7-Zip, PGP/GnuPG, age, OpenSSL, BitLocker, LUKS, FileVault DMG,
KeePass, SQLCipher) plus a Shannon-entropy fallback for headerless
encrypted containers (VeraCrypt / TrueCrypt style).

**Report only. Nothing here decrypts or cracks anything.**
"""

__version__ = "0.1.0"
