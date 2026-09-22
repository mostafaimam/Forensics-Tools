r"""memory_linux - best-effort Linux memory-image process-list recovery.

**Confidence & Validation - read before relying on this.** Unlike
Windows, where `_EPROCESS`/`_FILE_OBJECT`/etc. have a stable pool tag
this suite's other memory_* tools scan for regardless of exact field
offsets, Linux's `task_struct` has **no comparable stable signature**
at all, and its field offsets (and even its overall size) vary
significantly by kernel version *and build configuration* - there is
no single, version-independent structural anchor to scan for the way
`memory_timers` uses `DISPATCHER_HEADER` or `memory_dumpfiles` uses a
VACB's self-referential back-pointer.

Given that, this follows the same "examiner supplies the missing
piece" pattern `memory_hashdump`/`memory_lsasecrets` use for a SYSTEM/
SAM hive pair: **with a supplied profile** (a small JSON file naming
the kernel's direct-physical-map base, `init_task`'s virtual address,
and `task_struct`'s `tasks`/`comm`/`pid` field offsets for *this
specific kernel build* - obtainable from the target system's own debug
symbols, `/proc/kallsyms`, or a matching `vmlinux`), this performs a
genuine, verifiable doubly-linked-list walk of the `tasks` list
starting at `init_task`, translating kernel virtual addresses via
simple direct-map arithmetic (`pa = va - direct_map_base`, valid for
slab-allocated kernel objects in the direct-mapped region - a
real, if version-specific, technique, not a guess). **Without a
supplied profile**, it falls back to a much weaker heuristic: carving
16-byte NUL-terminated printable strings that could plausibly be a
`task_struct.comm` value, with no way to confirm any hit is actually
inside a task_struct at all - explicitly the lower-confidence path,
and clearly labelled as such in every row it produces.

Only a process list is in scope for v0.1 (no modules, network, or
history) - each is its own comparable undertaking.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
