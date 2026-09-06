"""memory_pslist - enumerate processes from a Windows RAM dump.

Pool-tag scanning (``psscan``): every ``Proc`` / protected-process pool
allocation in physical memory is a candidate ``_EPROCESS``.  Each candidate is
validated heuristically (a plausible image name, PID, and CreateTime) without
needing a per-build symbol profile, so it works on any Windows version and
surfaces **hidden and already-exited** processes.
"""

__version__ = "0.1.0"
