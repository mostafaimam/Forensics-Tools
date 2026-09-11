r"""memory_filescan - recover open _FILE_OBJECT names from a RAM dump.

Scans physical memory for the ``File`` pool tag every ``_FILE_OBJECT``
allocation carries, then reads the object body at a small set of
candidate offsets past the tag (the pool-header size has varied across
builds) looking for a plausible ``FileName`` ``UNICODE_STRING``: a
sane length pair and a buffer pointer in kernel space.  Because a file
object's name buffer lives in paged pool - kernel address space, mapped
identically in every process - it is resolved through **any** process's
page tables (or the kernel's own directory base), so no per-process
attribution step is needed to read it.

Recovers files that were open at capture time, including ones since
deleted from disk, with the device object each belongs to (a raw
`\Device\HarddiskVolumeN\...` path, not yet resolved to a drive letter).
Profile-independent; content-derived, so expect some partial rows.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
