"""memory_cmdline - process command lines from a Windows RAM dump.

For every process found by pool-tag scanning, the ``_EPROCESS`` is walked
to its user-space ``PEB`` and ``_RTL_USER_PROCESS_PARAMETERS`` to recover
the **full command line**, image path, current directory, window title and
(optionally) the environment block.  The PEB pointer offset is discovered
heuristically, so no per-build symbol profile is needed.

Command lines are the fastest way to spot living-off-the-land activity -
``powershell -nop -w hidden -enc ...``, ``certutil -urlcache``,
``rundll32 javascript:``, ``regsvr32 /i:http`` - and process masquerading
(the argv[0] name not matching the real image).
"""

__version__ = "0.1.0"
