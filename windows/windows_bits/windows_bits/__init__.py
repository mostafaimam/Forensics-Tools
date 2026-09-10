r"""windows_bits - BITS transfer-history forensics.

Reads the Background Intelligent Transfer Service job queue - the legacy
``qmgr0.dat`` / ``qmgr1.dat`` files and the modern ESE ``qmgr.db`` - and
lists every download / upload job it can recover: remote URL, local
destination, scratch file, owner SID, job type / state, byte counts and
create / modify times.

BITS is a routine malware download and exfiltration channel because the
transfer is performed by a system service, survives reboots and logoffs,
and is easy to miss.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
