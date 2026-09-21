"""browser_favicons - the icon-to-page-URL map that outlives history.

Reads Chromium's ``Favicons`` database (``icon_mapping`` /``favicons``/
``favicon_bitmaps``) and Firefox's ``favicons.sqlite`` (modern
``moz_icons`` / ``moz_pages_w_icons`` / ``moz_icons_to_pages`` schema).
Favicons are cached to make the UI feel fast, not for user-visible
history - so many "clear browsing data" flows leave them alone, and the
page URL a cached icon belongs to can outlive its own `History` row.
Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
