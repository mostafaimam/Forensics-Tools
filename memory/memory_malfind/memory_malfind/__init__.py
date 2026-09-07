"""memory_malfind - find injected / unbacked executable memory in a RAM dump.

Pool-tag scanning for ``VadS`` allocations - which are **private memory by
construction** (no mapped file behind them).  A private region that is also
**executable** is the classic signature of code injection: a reflectively
loaded DLL, a hollowed section, or raw shellcode.

No per-build symbol profile: the VPN pair sits at a stable offset in the
``_MMVAD_SHORT`` node and the protection bits are read from both known
positions (Windows 7 vs 8+).  Each region is attributed to a process by
testing candidate directory-table bases, then its first bytes are read
through the page tables and classified (PE header, shellcode prologue,
high-entropy RWX, header not paged in).
"""

__version__ = "0.1.0"
