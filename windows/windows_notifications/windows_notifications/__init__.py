r"""windows_notifications - parse wpndatabase.db (the toast / tile history).

Reads the Windows Push Notification store
(``…\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db``, a
SQLite database) and joins the ``Notification`` table to
``NotificationHandler`` so every notification is attributed to an
application (its AUMID or executable id).

Per notification: the app, the type (``toast`` / ``tile`` / ``badge`` /
``raw``), the arrival and expiry times (FILETIME -> UTC), the tag / group,
and the **notification text** - extracted from the toast / tile payload
XML.

The evidence file is copied with its WAL side files before opening, so the
original is untouched.  Flags notifications from living-off-the-land /
script apps, text that contains a URL or an IP literal, and ``raw``
notifications (a channel some implants use).  Pure standard library,
read-only.
"""

__version__ = "0.1.0"
