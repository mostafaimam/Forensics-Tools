r"""macos_unifiedlog - best-effort Apple Unified Logging (.tracev3) reader.

**Confidence & Validation - read before relying on this.** The
top-level tracev3 chunk framing (a 4-byte tag, 4-byte sub-tag, 8-byte
payload length, repeated) is a simple TLV structure cited consistently
across public research (Mandiant's write-ups, the open-source
UnifiedLogReader project) - this project has moderate-good confidence
in it. LZ4 block decompression itself (`lz4block.py`) is a public,
well-specified algorithm implemented here with high confidence, the
same way this suite's `browser_localstorage` hand-rolled Snappy
decompression from its own public spec.

What is **not** confidently known: the exact byte framing Apple wraps
around that LZ4 data inside a ChunkSet chunk (the "bv41"/"bv4-" magic
and the header fields around it), and - far more so - the internal
Firehose record format (proc/activity IDs, timestamp deltas, and the
item-type-tagged argument encoding needed to substitute values into a
log message's format string). Resolving a message's actual text also
needs the `uuidtext` / `dsc` shared-cache files, whose binary layout
this project has no verified reference for at all.

Given that, v0.1 deliberately stops at: chunk inventory (tag, offset,
length) for every top-level and ChunkSet-nested chunk; best-effort LZ4
decompression of ChunkSet payloads, self-verified by checking the
decompressed bytes parse as a valid nested-chunk sequence rather than
trusted blindly; and generic printable-string carving from Firehose/
Oversize/StateDump payloads (literal message fragments, subsystem
names, and similar often survive as raw strings even without full
format-string resolution). It does **not** produce fully formatted,
human-readable log lines the way `log show` or a reference tool would -
see the README before treating this as a complete .tracev3 parser.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
