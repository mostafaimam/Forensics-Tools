r"""cloud_gdrive - locate and generically inspect Google Drive for
Desktop sync-client metadata (``%LOCALAPPDATA%\Google\DriveFS\
<account_id>\`` / ``~/Library/Application Support/Google/DriveFS/``).

``metadata_sqlite_db`` (item inventory: Google file IDs, names,
parents, versions) and ``snapshot.db`` are, like every cloud-sync
-client database this suite's cloud/ tools cover, a **proprietary,
undocumented** schema - unlike the audit-log tools (CloudTrail, Entra
ID, M365 UAL, Workspace), which read a vendor's own published format.
Unlike Dropbox's `.dbx` files, these are typically **not** encrypted,
so v0.1 can usually read real content: every table is dumped
generically, in full, with only conservative column-name hints layered
on top - no claimed understanding of the actual `items`/`stable_ids`
schema (parent-path reconstruction, trashed-item state, and
shared-drive handling from the original spec stub are all deferred;
see the README).
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
