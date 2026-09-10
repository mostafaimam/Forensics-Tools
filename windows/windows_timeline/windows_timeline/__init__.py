r"""windows_timeline - parse the Windows 10/11 Timeline (ActivitiesCache.db).

Reads the ``ConnectedDevicesPlatform\<profile>\ActivitiesCache.db`` SQLite
store that backs the Windows Timeline / "Activity History" feature.

Per activity: the type (open-app / open-file / in-app / clipboard /
copy-paste / notification), the resolved application (the Win32 path or
the packaged-app id from the ``AppId`` JSON), the display text and content
URI from the ``Payload`` JSON, the start / end / last-modified times
(Unix seconds -> UTC) and the on-disk duration, plus the local-only /
in-cloud flags.  Base64 ``ClipboardPayload`` blobs are decoded to their
text.  ``ActivityOperation`` rows (pending sync, often holding *removed*
activities) are included and marked.

The evidence file is never modified - it is copied with its WAL side
files first.  Flags apps / content in a user-writable path, LOLBins,
``file://`` URIs into Temp and secret-looking clipboard captures.  Pure
standard library, read-only.
"""

__version__ = "0.1.0"
