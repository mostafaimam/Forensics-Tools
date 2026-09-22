r"""memory_dumpfiles - best-effort cached-file-content reconstruction
from the Windows Cache Manager.

**Confidence & Validation.** Locating `_FILE_OBJECT` structures by the
``File`` pool tag and reading their name field (reused from
`memory_filescan`) is the same moderate-good-confidence technique the
rest of this suite's pool-tag-scan tools use. Walking onward -
`_FILE_OBJECT.SectionObjectPointer` -> `_SECTION_OBJECT_POINTERS.
SharedCacheMap` -> `_SHARED_CACHE_MAP.InitialVacbs[4]` -> each
`_VACB.BaseAddress` - needs field OFFSETS this project does not have a
symbol server to resolve exactly, and that have genuinely drifted
across Windows versions in the public literature this project's
recollection draws on.

Rather than hardcode one guessed offset per field (fragile, silently
wrong on the next build), each step **scans a plausible offset window**
and keeps only a candidate that **self-verifies**: a `_VACB` is only
accepted if its own back-pointer field (which should point at the
`_SHARED_CACHE_MAP` it came from) actually does - the same
self-referential consistency check `pagemap.py` already uses to
confirm a directory-table-base guess (Windows maps its own PML4 into
itself; a wrong guess fails that check near-certainly). A `_VACB`
passing that check is a strong, not just plausible, signal. `BaseAddress`
is still trusted to point at 256 KiB of genuinely cached file content
once verified this way - never presented as recovered without the
check passing.

Only what the Cache Manager still has resident is recoverable this way
- gaps in a file's cached ranges are reported as gaps, not
zero-filled and presented as real content.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
