"""linux_journal - read the systemd journal (``.journal``) binary format.

A from-scratch reader for systemd journal files.  It scans the object arena
linearly, picks out ENTRY objects, resolves each entry's DATA objects into
``FIELD=value`` pairs and yields one record per entry with the realtime
(UTC) and monotonic timestamps, the boot id and every field.

Handles the regular and COMPACT on-disk layouts and XZ-compressed data
objects (stdlib ``lzma``).  LZ4- and ZSTD-compressed objects cannot be
inflated with the standard library alone and are surfaced as a short
placeholder plus a partial-parse warning.

Filters on any field (``_SYSTEMD_UNIT``, ``_PID``, ``PRIORITY``,
``_BOOT_ID`` ...), a priority threshold, a time window and a boot id;
merges several files into one ordered timeline.  Pure standard library.
"""

__version__ = "0.1.0"
