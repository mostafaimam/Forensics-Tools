r"""memory_registry - locate registry hives loaded in a Windows RAM dump.

Scans physical memory for the ``regf`` hive base-block signature - every
loaded hive keeps this 4 KiB header memory-resident - and reads it
directly: the embedded file path, the sequence numbers (mismatched =
**dirty**, unflushed changes), the last-written FILETIME, and the format
version.  This recovers hives that were mapped at capture time,
including ones whose backing file was later deleted, without needing a
``_CMHIVE`` / ``_HHIVE`` structure offset for the running build.

Full hive-body reconstruction (walking the in-memory cell map to rebuild
a file `windows_registry` can open) is not yet implemented - see
Limitations; v0.1 is the hive **list** with per-hive dirty status.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
