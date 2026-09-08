"""browser_logins - saved-login METADATA only (never the password).

Lists the saved-credential records from Chromium ``Login Data`` and
Firefox ``logins.json`` (+ ``key4.db`` presence): origin, sign-on realm,
username, created / last-used / password-changed times, use count and the
never-save exclusion list.

Passwords stay encrypted and are **never** decrypted or emitted - the
tool reports only that an encrypted password blob exists.  Read-only and
WAL-safe.  Pure standard library.
"""

__version__ = "0.1.0"
