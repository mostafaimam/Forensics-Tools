"""browser_sessions - the tabs and windows open at last browser close.

Reconstructs the browsing session from:

* Chromium ``Sessions/Session_*`` / ``Tabs_*`` and ``Last Session`` /
  ``Current Session`` - the SNSS command-stream (magic ``SNSS``)
* Firefox ``sessionstore.jsonlz4`` and ``sessionstore-backups/*.jsonlz4``
  (``mozLz4`` container + a bundled LZ4 block decoder)

Each tab is one row: window, position, pinned state, current URL / title,
navigation-history depth, last-accessed time, and whether it was a closed
(recently-closed) tab.  Restored form data, closed-tab retention and
sign-in pages are flagged.  Read-only.  Pure standard library.
"""

__version__ = "0.1.0"
