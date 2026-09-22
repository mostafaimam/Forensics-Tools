r"""memory_macos - best-effort macOS (XNU) memory-image process-list
recovery.

**Confidence & Validation - read before relying on this.** XNU's BSD
-layer `proc` structure has no stable cross-version signature the way
Windows kernel objects in this suite have a pool tag, and macOS kernel
memory forensics has meaningfully less public community tooling and
documentation than even Linux's equivalent problem - this project's
confidence here is the lowest of this suite's memory/ tools.

Follows the same "examiner supplies the missing piece" pattern
`memory_linux` uses for the analogous Linux problem, adapted to XNU's
structure: **with a supplied profile** (a small JSON naming the
kernel's direct-physical-map base, the `allproc` list's first `proc`
pointer value, and `proc`'s `p_list.le_next`/`p_comm`/`p_pid` field
offsets - obtainable from the target system's own kernel debug
symbols), this performs a genuine, verifiable walk of the **BSD
`LIST`** the `allproc` global anchors (NULL-terminated, unlike Linux's
circular `tasks` list - a real, different structural convention, not
a copy-paste of the Linux tool), translating kernel virtual addresses
via simple direct-map arithmetic. **Without a supplied profile**,
falls back to the same weak heuristic comm-string carving `memory_linux`
uses when unsupplied, with the identical caveat: no way to confirm any
hit is actually inside a `proc` structure.

Only a process list is in scope for v0.1.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
