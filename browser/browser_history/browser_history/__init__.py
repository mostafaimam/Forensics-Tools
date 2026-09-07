"""browser_history - web history, downloads and typed URLs from a disk image.

Reads the Chromium family (Chrome / Edge / Brave / Opera / Vivaldi),
Firefox / Tor Browser, and Safari history stores directly with the
standard-library ``sqlite3`` module - **read-only, WAL-safe, the file is
never modified** - and normalises everything to one schema: URL, title,
UTC visit time, visit count, whether the user *typed* it, the transition
type, and the source profile.

Downloads (source URL, referrer, target path, bytes, danger flag) and the
search terms behind search-engine visits are pulled from the same stores.
Suspicious URLs - IP-literal hosts, punycode, paste / anonymiser sites,
`file://` access, very long or base64-laden URLs - are flagged.
"""

__version__ = "0.1.0"
