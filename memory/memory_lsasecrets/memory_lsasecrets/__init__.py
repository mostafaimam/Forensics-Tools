r"""memory_lsasecrets - decrypt LSA secrets given a SYSTEM + SECURITY
hive pair. Reporting only, and IR-scoped exactly like memory_hashdump:
the LSA key is recoverable from the SYSTEM hive alone (no examiner
-supplied secret needed), and this reports the plaintext secret
values Windows itself must be able to read at boot - it does not crack
or brute-force anything.

LSA secrets (``SECURITY\Policy\Secrets\<name>\CurrVal``) hold service
-account passwords (``_SC_*``), the machine's DPAPI backup key material,
auto-logon passwords (``DefaultPassword``), and cached RAS/VPN
credentials - unlike a SAM hash, several of these decrypt straight back
to a plaintext password, so their exposure is often more immediately
actionable than a hash.

v0.1 takes SYSTEM and SECURITY as **hive files** (see memory_hashdump's
docstring for why: reconstructing a hive body from a raw memory image is
a separate, harder undertaking than memory_registry's hivelist), and
covers only the **modern (PolEKList/AES) key scheme** - the legacy
pre-Vista DES-X scheme and MSCACHE domain-logon-verifier extraction are
both out of scope for v0.1 (see the README).
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
