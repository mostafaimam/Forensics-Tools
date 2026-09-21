"""browser_localstorage - a from-scratch LevelDB reader for browser data.

Chromium's Local Storage and IndexedDB are backed by LevelDB databases on
disk: a write-ahead log (``*.log``) of recent writes plus sorted-string
table files (``*.ldb``) the log periodically compacts into. Both formats
are public and stable (Google's own LevelDB project); this package
implements them from scratch (varint decode, CRC32C record/block
checksums, the WriteBatch log-record format, and the SSTable
index/data-block layout, including a pure-Python Snappy block
decompressor since blocks are Snappy-compressed by default).

**Every key/value ever written is read, not just the current live
value.** LevelDB never overwrites a record in place - a later write or a
deletion is a *new* record with a higher sequence number, and old
records linger in older ``.log``/``.ldb`` files until compaction removes
them. That means a value the app "deleted" or overwrote is often still
sitting in an old log or table file, exactly like a stale MFT record or
an old registry value elsewhere in this suite. Read-only.

Scope: the generic LevelDB engine (log + sstable + snappy) is exact and
self-tested. The Local-Storage-specific origin/key-schema split (the
``_<origin>\\x00<key>`` convention and the string-value type-byte prefix)
is Chromium-internal and undocumented, so it is applied heuristically and
labeled accordingly - see the README. IndexedDB object-store value
deserialization is out of scope for v0.1; IndexedDB directories are read
by the same generic engine and surfaced as raw key/value pairs.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
