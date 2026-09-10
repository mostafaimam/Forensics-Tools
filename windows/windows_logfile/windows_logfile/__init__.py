r"""windows_logfile - NTFS ``$LogFile`` transaction-log forensics.

Parses ``$LogFile`` - the NTFS metadata journal - into recent file-system
transactions.  It reads the ``RSTR`` restart pages and the ``RCRD`` record
pages (fixing the update-sequence array), walks the log-record stream,
decodes the redo / undo operations, and pulls the ``FILE_NAME`` attribute
out of the index-entry operations to reconstruct high-level events: **file
created**, **file deleted**, **renamed**, **MFT record initialised /
freed**, **resident data written**.

``$LogFile`` covers only the last few tens of MB of metadata activity, but
at a finer grain and often slightly ahead of ``$UsnJrnl``.  Read-only.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
