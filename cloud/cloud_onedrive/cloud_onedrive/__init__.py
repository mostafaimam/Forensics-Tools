r"""cloud_onedrive - locate and generically inspect OneDrive sync-client
metadata (``%LOCALAPPDATA%\Microsoft\OneDrive\settings\<Personal|
BusinessN>\``).

OneDrive's local metadata is a **proprietary, undocumented** format
that has changed shape across client versions (SQLite in current
clients, ESE/JET in older ones) and has no public specification -
unlike this suite's cloud audit-log tools (CloudTrail, Entra ID, M365
UAL, Workspace), which all read Microsoft/AWS/Google's own published
schemas. Rather than guess at column semantics this project cannot
verify, v0.1 locates the known settings directory, parses the plain
``*.ini``-shaped settings files there (a real, unambiguous format), and
generically dumps every table of ``SyncEngineDatabase.db`` if it's
SQLite - full fidelity, honest about not claiming to understand the
vendor's internal schema beyond conservative column-name hints (a
column named something like ``path`` or ``time`` is labeled as such;
nothing is inferred beyond that). An ESE-format database (older
clients) is detected and handed off: this project's own
`windows_esedb` tool already reads that format directly.

ODL activity-log de-obfuscation (mentioned in the original spec stub)
is out of scope for v0.1 - see the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
