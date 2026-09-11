r"""mounting_bitlocker - unlock a BitLocker volume with a supplied secret.

Given a **recovery password** (the 48-digit key), parses the FVE
metadata block, derives the intermediate key with BitLocker's key-
stretching KDF (SHA-256 chained ``0x100000`` times with the protector's
salt), AES-CCM-unwraps the Volume Master Key, then unwraps the Full
Volume Encryption Key with it - and can then decrypt an arbitrary
sector range with the resulting AES-CBC or AES-XTS keys.  The examiner
supplies the password; nothing is brute forced.

Ships its own AES (ECB / CBC / CTR / XTS) and a generic AES-CCM
implementation (NIST SP 800-38C), since neither is in the standard
library.  Read-only; IR-scoped.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
