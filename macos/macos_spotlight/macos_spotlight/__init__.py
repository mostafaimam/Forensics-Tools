r"""macos_spotlight - Spotlight metadata store artifact carver.

``.spotlight-V100/Store-V2/<UUID>/store.db`` (and the older
``.Spotlight-V100/*.store.db``) hold Apple's per-volume Spotlight index:
every file's ``kMDItem*`` metadata attributes, packed into a proprietary,
undocumented binary format (dictionary blocks mapping attribute/category
names to small integer IDs, page-based record blocks referencing those
IDs). No public specification of the on-disk layout exists, and getting
the block/varint decoding byte-exact without a reference implementation
to validate against is not something this project can represent with
confidence.

Rather than guess at an unverifiable page format, this tool takes a
carving approach: it decodes ASCII and UTF-16LE string runs directly from
the raw store file and classifies each one against Spotlight-specific
patterns - ``kMDItem*`` attribute names, Uniform Type Identifiers,
reverse-DNS bundle identifiers, download-provenance URLs
(``kMDItemWhereFroms`` values are stored as plain URL strings), and
absolute macOS paths. This recovers real forensic signal (what a file's
attributes were, where it was downloaded from, what app opened it) even
from a deleted or partially-overwritten store, without claiming to
reconstruct records this project cannot verify. Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
