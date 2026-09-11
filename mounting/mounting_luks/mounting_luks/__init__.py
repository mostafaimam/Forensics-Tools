r"""mounting_luks - unlock a LUKS volume with a supplied passphrase or key.

Parses a **LUKS1** header, tries the supplied passphrase against each
active key slot (PBKDF2-HMAC with the slot's own salt / iteration count,
AES-CBC-ESSIV decrypt of the anti-forensic-split key material, AF-merge
to recover the candidate master key, verified against the header's
master-key digest), and - once the master key is known - decrypts an
arbitrary sector range of the payload.

LUKS2 headers are recognised and their JSON metadata / key-slot layout
reported, but LUKS2's default KDF (Argon2id) is not implemented, so a
LUKS2 volume is not unlockable in v0.1 - see Limitations.  The examiner
supplies the secret; nothing is brute forced.

Ships its own AES (ECB / CBC / XTS) since it is not in the standard
library.  Read-only; IR-scoped.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
