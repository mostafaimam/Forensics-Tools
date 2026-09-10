r"""macos_fsevents - parse the /.fseventsd file-system change log.

Reads the gzip-compressed binary logs under ``/.fseventsd`` (or
``/System/Volumes/Data/.fseventsd`` on APFS) - the record macOS keeps of
every create / delete / rename / modify on the volume, for weeks.

Each log file starts with a ``DLS1`` / ``DLS2`` / ``DLS3`` page magic and
holds records of ``<path> <event-id> <flags> [<node-id>]``.  There is no
per-record timestamp - the event id is a monotonic counter - so ordering
is by event id and the approximate time comes from the log file's own
name range and mtime (surfaced as ``approx_time``).

Per record: the path, the decoded change flags (Created / Removed /
Renamed / Modified / FolderCreated / InodeMetaMod / XattrModified / ...),
the event id, the node (inode) id, and the source log file.  Flags
create / delete in sensitive or user-writable locations, deletion of
security artefacts (TCC.db, quarantine, shell history, XProtect), and
create-then-remove churn.  Pure standard library, read-only.
"""

__version__ = "0.1.0"
