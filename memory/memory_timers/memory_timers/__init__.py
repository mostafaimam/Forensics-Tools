r"""memory_timers - enumerate Windows kernel timers (KTIMER) from a
64-bit memory image via structural validation, not a global-list-head
symbol.

Every KTIMER begins with a DISPATCHER_HEADER - a small, stable,
publicly documented structure (in the WDK / Windows Research Kernel
headers) shared by every kernel synchronization object. Its ``Type``
byte is one of a fixed, documented set of ``KOBJECTS`` enum values;
timers are ``TimerNotificationObject`` (8) or ``TimerSynchronizationObject``
(9). That means every KTIMER in memory carries a small, checkable
signature - the same "profile-independent structural scan" approach
this suite's other Windows memory tools use (pool-tag scanning for
processes/files/services), as opposed to needing ``KiTimerTableListHead``
or any other unexported kernel symbol this project has no way to
resolve without a symbol server.

This is different from - and more confident than - a "no public spec"
deferral like `mounting_vsc`: the DISPATCHER_HEADER/KTIMER layout is
documented, just scattered rather than pool-tagged, so this tool
validates structural plausibility (Type byte, a size-field range, and
canonical-kernel-pointer checks on the embedded list/DPC pointers)
instead of scanning for a 4-byte ASCII tag. x64 only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
