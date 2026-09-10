r"""macos_netusage - per-process network usage from netusage.sqlite.

Reads ``/private/var/networkd/netusage.sqlite`` - the per-process
network-accounting store macOS keeps for Wi-Fi Assist and data
management.

* ``ZLIVEUSAGE`` joined to ``ZPROCESS`` gives one row per process: the
  cumulative **bytes in / out** split by interface class (Wi-Fi / WWAN /
  wired), the first-seen and last-seen timestamps (Mac absolute time ->
  UTC);
* ``ZNETWORKATTACHMENT`` gives the interface / SSID usage windows.

This is the macOS equivalent of Windows SRUM's network table - it
answers "which executable sent how much data, over which link, and
when".

Flags large or upload-only egress, network usage by a shell / scripting
interpreter or a binary in a user-writable path, and cellular (WWAN)
usage by an unexpected app.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
