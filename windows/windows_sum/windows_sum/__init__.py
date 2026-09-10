r"""windows_sum - Microsoft User Access Logging (SUM) forensics.

Reads the User Access Logging databases under
``C:\Windows\System32\LogFiles\SUM`` - ``SystemIdentity.mdb`` (role GUID ->
product name, host identity) and the rolling ``Current.mdb`` /
per-year ``{GUID}.mdb`` role databases - and emits one row per
(user, client, role) access aggregate: authenticated user, client name and
IP address, the server role accessed, first / last seen, total access
count and duration, and the per-day access histogram.

UAL is on by default on Windows Server and is one of the richest
lateral-movement and "who connected to this box" sources on a dead disk.
Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
