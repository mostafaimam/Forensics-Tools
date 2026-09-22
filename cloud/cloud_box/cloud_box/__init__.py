r"""cloud_box - locate and generically inspect Box Drive local
metadata (``%LOCALAPPDATA%\Box\Box\`` / ``~/Library/Application
Support/Box/Box/``).

Box Drive's local database format is a **proprietary, undocumented**
schema with meaningfully less public forensic documentation than
OneDrive, Dropbox, or Google Drive's equivalents - this project does
not have a confident specific filename to look for the way it does for
the other three (`SyncEngineDatabase.db`, `filecache.dbx`,
`metadata_sqlite_db`). Rather than guess at a name, v0.1 searches any
directory whose path mentions Box for *any* SQLite-format file at all
and dumps it generically, table by table - full row fidelity, no
claimed understanding of the schema beyond conservative column-name
hints. This is deliberately broader and less targeted than this
suite's other three cloud-sync tools; see the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
