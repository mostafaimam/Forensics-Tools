r"""memory_hashdump - extract local NT/LM password hashes given a
SYSTEM + SAM hive pair. Reporting only: this derives the SYSTEM hive's
own "boot key" and uses it to decrypt each account's stored hash -
Windows' own key-derivation chain, which needs no examiner-supplied
secret at all (unlike BitLocker/LUKS/VeraCrypt, there is no password to
"not brute force" here: the boot key is recoverable from the SYSTEM
hive alone, by design, since Windows itself must be able to do this at
every boot). Cracking the resulting hashes into plaintext passwords is
a separate step this project does not perform.

v0.1 takes SYSTEM and SAM as **hive files**, not a raw memory image:
reconstructing a full, byte-exact hive body from scattered/paged memory
(as opposed to just locating hive headers, which `memory_registry`
already does) is a separate, harder undertaking not yet built. Extract
the two hives from the target first (a mounted image, `acquisition_collect`,
or a live-registry export) and point this tool at the files.

Supports both the legacy (pre-Vista, RC4 + RID-keyed-DES) and the
modern (AES) SAM encryption schemes - see the README for which parts of
each are high-confidence (decades of independent, cross-validated public
implementations) versus this project's best-effort reading of
undocumented modern struct offsets.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
