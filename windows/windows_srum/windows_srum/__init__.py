r"""windows_srum - parse SRUDB.dat (System Resource Usage Monitor).

Reads the SRUM ESE database (`C:\Windows\System32\sru\SRUDB.dat`) and
turns it into one normalised timeline row per application per hourly
bucket, across every known provider:

* **network-data** - bytes sent / received per app per interface
* **network-connectivity** - connected seconds + connection start time
  per interface
* **application-resource** - foreground / background CPU cycle time and
  bytes read / written per app
* **energy-usage** - per-app energy consumption (and the long-term table)
* **push-notifications** - notification payload / network bytes per app

`SruDbIdMapTable` is used to resolve the numeric ``AppId`` / ``UserId``
foreign keys to application id strings (usually the full executable path)
and user SIDs.

Flags apps that ran from a user-writable path, large outbound transfers,
living-off-the-land binaries with network usage and unusual providers.
Vendors :mod:`windows_esedb`; pure standard library, read-only.
"""

__version__ = "0.1.0"
