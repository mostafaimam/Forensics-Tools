"""browser_bookmarks - the bookmark tree with added / modified times.

Reads the Chromium ``Bookmarks`` JSON (and diffs it against
``Bookmarks.bak`` to surface deleted entries) and Firefox
``moz_bookmarks`` in ``places.sqlite``.

Each bookmark is one row: the full folder path, title, URL, and the
date it was added and last modified.  Bookmarklets (``javascript:``
URLs), ``file://`` / ``ftp://`` targets and bookmarks that survive only
in the ``.bak`` are flagged.  Read-only and WAL-safe.  Pure standard
library.
"""

__version__ = "0.1.0"
