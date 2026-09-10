r"""windows_sdb - Application Compatibility shim-database forensics.

Parses ``.sdb`` files - the system ``sysmain.sdb`` and, more interestingly,
custom / installed databases - and lists the shims, patches and their
target executables.  A custom SDB is a documented persistence and
code-injection vector: an ``InjectDll`` shim (or a binary ``PATCH``) bound
to a system executable runs attacker code every time that executable
starts, and the only on-disk trace is the ``.sdb`` plus an ``InstalledSDB``
registry entry.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
