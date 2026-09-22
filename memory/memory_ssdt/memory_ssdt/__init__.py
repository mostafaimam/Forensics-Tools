r"""memory_ssdt - best-effort SSDT-shaped function-pointer table scan.

**Confidence & Validation - read before relying on this.** The classic
"inspect the SSDT for hooks" technique targets `KeServiceDescriptorTable`,
which is an **unexported** kernel global on x64 Windows with no stable
public offset - and on any modern build with PatchGuard active, the
real syscall dispatch table cannot legitimately be hooked at runtime
the way this technique originally assumed, since PatchGuard actively
protects it. **On a typical modern 64-bit Windows 10/11 image, expect
this tool to find nothing meaningful, or nothing at all** - that is
the correct, honest outcome, not a bug.

What this still does, with genuine (not obsolete) value: locates
ntoskrnl.exe in the image via its PE export directory (the PE format
itself is fully public and precisely specified by Microsoft - high
confidence, unlike anything reverse-engineered-only elsewhere in this
batch), confirmed by the presence of a small set of well-known kernel
export names. It then scans nearby memory for **candidate**
function-pointer arrays where the large majority of entries point
inside ntoskrnl's own mapped code range - a real structural property a
syscall table (or any legitimate kernel dispatch table) has - and flags
any entries that *don't*, as a possible hook. This is reported as a
candidate array with flagged anomalies, not a confirmed, symbol
-resolved SSDT - there is no way to be certain a given candidate array
is *the* SSDT specifically rather than some other similarly-shaped
kernel table, and this project has not verified this against a real
Windows image. Treat any flagged entry as a lead requiring
corroboration (e.g. against a live-system SSDT dump), not as a
confirmed hook.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
