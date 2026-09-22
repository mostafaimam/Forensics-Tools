r"""memory_callbacks - best-effort kernel notification-callback array
scan (process/thread/image-load and similar small, mostly-empty
pointer tables).

**Confidence & Validation - read before relying on this.** The actual
kernel globals holding these arrays (e.g. the process-creation
notify-routine array behind `PsSetCreateProcessNotifyRoutineEx`) are
**unexported** on x64 Windows with no stable public offset this
project can resolve without a symbol server - the standard technique
elsewhere (Volatility3's callbacks plugin, for one) locates them via
x86-64 disassembly of the registration functions' code, a genuinely
different and more involved technique this project has not
implemented.

Instead, this scans physical memory for small, **fixed-size, mostly
-NULL** pointer arrays (the normal shape of these tables - most
callback slots are simply unregistered) whose non-NULL entries are all
canonical kernel pointers and cluster together, the same clustering
idea `memory_ssdt` uses for the (much larger, fully-populated) SSDT.
Low-order bits of a stored pointer are masked off before the canonical
check, since some Windows callback-array conventions use them as
flags. **This never claims a given candidate array is a specific named
callback table** - there is no symbol resolution here to confirm which
kernel global (if any) it corresponds to, and this has not been
verified against a real Windows image. Every non-NULL entry found is
reported as a real, checkable candidate registered callback; any entry
that doesn't fit the rest of its array's cluster is flagged as a
possible anomaly - both are investigative leads, not confirmed
findings.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
