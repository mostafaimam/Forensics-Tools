r"""memory_handles - per-process open file handles from a Windows RAM dump.

For each process found by the light ``_EPROCESS`` scan, this locates
``ObjectTable`` by validating candidate offsets against the resulting
``_HANDLE_TABLE`` shape (a plausible level count and a page-aligned base),
walks the (1-3 level) table, and decodes each ``_HANDLE_TABLE_ENTRY`` to
an object-header address - trying the handful of bit-layouts Windows has
used across releases and keeping whichever yields a valid object.  Each
resolved object is checked against the ``_FILE_OBJECT`` shape (the same
``FileName`` ``UNICODE_STRING`` content-check ``memory_filescan`` uses)
and, when it matches, reported as ``(pid, process, handle value, path)``.

v0.1 recovers **file handles only** - see Limitations for why key,
process, thread and section handles are not yet typed.  Profile-
independent; content-derived, so expect some partial or missed rows.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
