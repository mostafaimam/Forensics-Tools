r"""macos_powerlog - parse CurrentPowerlog.PLSQL (the macOS PowerLog).

Reads the PowerLog SQLite database
(``/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL``
and the archived ``Powerlog_*.PLSQL.gz``).  PowerLog logs app usage,
process starts, camera / microphone / location use and battery state
with second-level timestamps going back days.

This tool normalises the high-value ``PL*Agent*`` tables into one event
timeline:

* **app usage / foreground** - which bundle id, when;
* **process start / stop** - process name + pid;
* **camera / microphone in use** - which client;
* **location fix** - latitude / longitude, and the client that asked;
* **battery level** and **lightning / power state**;
* **bulletin / notification** delivery.

Timestamps are decoded (Unix or Mac-absolute, auto-detected) to UTC.
``--list-tables`` and ``--table NAME`` give a raw dump of any table.
Flags camera / mic use by a non-media app, a shell / interpreter process
start and a location fix while the device is locked.  Pure standard
library, read-only.
"""

__version__ = "0.1.0"
