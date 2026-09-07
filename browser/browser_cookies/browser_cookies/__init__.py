"""browser_cookies - cookies from the browser stores on a disk image.

Reads the Chromium family (Chrome / Edge / Brave / Opera / Vivaldi),
Firefox / Tor Browser (``cookies.sqlite``) and Safari
(``Cookies.binarycookies``) - **read-only, WAL-safe, evidence never
modified** - and normalises every cookie: host, name, path, expiry,
creation and last-access time, the `Secure` / `HttpOnly` / `SameSite`
flags, and whether it is a session cookie.

Cookie **values are not printed by default** (Firefox stores them in the
clear; Chromium encrypts them).  ``--with-values`` opts in for the
plaintext stores.  Session / authentication cookies, cookies for
IP-literal or tunnel hosts, mis-prefixed ``__Host-`` / ``__Secure-``
names and implausibly long-lived cookies are flagged.
"""

__version__ = "0.1.0"
