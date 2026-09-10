r"""recovery_fs - one read-only walker for any supported file system.

Detects the file system at a given offset (or auto-detects the first
partition) and walks it through one API: list files (allocated **and**
deleted), extract by path / inode, ``cat`` a single file, and emit a
3.x-format bodyfile for ``analysis_timeline``.

Backends in v0.1: **NTFS** (the vendored ``recovery_metadata`` engine),
**FAT12 / FAT16 / FAT32** and **exFAT** - between them the common Windows
and removable-media cases.  ext / HFS+ / APFS are detected and reported
but not yet walkable.
"""

__version__ = "0.1.0"

from recovery_fs.engine import Backend, FsEntry  # noqa: F401
