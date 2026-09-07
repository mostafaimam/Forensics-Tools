"""memory_svcscan - Windows services from a RAM dump.

The Service Control Manager keeps every service as a ``_SERVICE_RECORD`` in
``services.exe``'s heap, tagged ``sErv``.  Scanning physical memory for the
tag and resolving each record's pointers through ``services.exe``'s address
space recovers the service list **without the registry** - including
services that were deleted from ``HKLM\\SYSTEM\\...\\Services`` but are
still registered with the SCM.

No per-build symbol profile: name, display name, type, state and binary
path are found by content.  Services whose binary runs from a
user-writable directory, is a LOLBin, has no path, or has a random-looking
name are flagged.
"""

__version__ = "0.1.0"
