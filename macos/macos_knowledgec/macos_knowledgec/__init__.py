r"""macos_knowledgec - the CoreDuet knowledgeC.db activity store.

Reads ``knowledgeC.db`` (SQLite) - the store behind Siri suggestions and
Screen Time:

* ``/private/var/db/CoreDuet/Knowledge/knowledgeC.db`` (system);
* ``~/Library/Application Support/Knowledge/knowledgeC.db`` (user).

The ``ZOBJECT`` table is a stream of timestamped events.  This tool
decodes the forensically useful streams:

* ``/app/usage`` / ``/app/inFocus`` - which application, when, for how
  long;
* ``/app/webUsage`` / ``/safari/history`` - which web domain / page;
* ``/display/isBacklit`` - screen on / off;
* ``/device/isLocked`` / ``/device/isPluggedIn`` - lock and power state;
* ``/app/intents`` - Siri / Shortcuts invocations;
* ``/app/mediaUsage`` / ``/notification/usage``.

Each row: stream, value (bundle id / domain), start / end (Mac absolute
time -> UTC), duration, the device id, the recorded GMT offset and any
metadata title.  Flags long Terminal / scripting-app sessions, web usage
of paste / tunnel sites, activity while the screen is off, and bundle ids
that are an absolute path.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
