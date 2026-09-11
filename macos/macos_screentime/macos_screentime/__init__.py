r"""macos_screentime - Screen Time app / category usage (RMAdminStore).

Reads the Screen Time "Remote Management" admin store -
``RMAdminStore-Local.sqlite`` under
``/private/var/folders/**/com.apple.ScreenTimeAgent/`` (or wherever it
was collected to) - a per-app and per-category **daily usage total**
store, including usage synced in from the other devices on the same
Apple ID.

The store is a Core Data SQLite database, and Core Data's own schema
convention is used to read it without a hard-coded, version-specific
table map: the ``Z_PRIMARYKEY`` table names every entity
(``ZRMDEVICE``, ``ZRMAPPUSAGE``-shaped tables, …), and this module finds
the usage-shaped ones by their columns (a bundle / app identifier, a
duration or start/end pair, a date) rather than assuming exact names -
so it keeps working across the schema drift between macOS releases.
Event-level detail (individual app-focus sessions) lives in
``knowledgeC.db`` - see ``macos_knowledgec`` - this tool is the daily
*totals* view Screen Time itself reports.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
