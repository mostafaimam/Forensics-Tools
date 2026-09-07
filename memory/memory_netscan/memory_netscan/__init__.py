"""memory_netscan - network connections and sockets from a Windows RAM dump.

Pool-tag scanning for ``tcpip.sys`` allocations (``TcpE`` endpoints,
``TcpL`` listeners, ``UdpA`` endpoints).  Each candidate is parsed by
content - a plausible ``CreateTime``, big-endian ports, a TCP-state enum,
kernel pointers that resolve - so no per-build symbol profile is needed;
**hidden and already-closed connections** that a live ``netstat`` misses
are recovered.

When the kernel directory-table base can be found (from a crash-dump
header, or by locating a ``System``-like ``_EPROCESS`` and confirming its
page tables via the self-referential PML4 entry), the owning process and
the local / remote addresses are resolved by following the endpoint's
pointers.  Without it the row is still reported from whatever was inline,
at lower confidence.
"""

__version__ = "0.1.0"
