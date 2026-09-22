"""Build a synthetic Google Drive for Desktop metadata database."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def build_tree(root: Path) -> Path:
    account = root / "Google" / "DriveFS" / "0ABCDefGhijKLmnoPQ"
    account.mkdir(parents=True)

    db = sqlite3.connect(account / "metadata_sqlite_db")
    db.execute("CREATE TABLE items (id TEXT, local_title TEXT, "
              "modified_date INTEGER, size INTEGER, is_folder INTEGER, "
              "trashed INTEGER)")
    db.execute("INSERT INTO items VALUES ('1', 'quarterly-report.pdf', "
              "1735689600, 102400, 0, 0)")
    db.execute("INSERT INTO items VALUES ('2', 'old-draft.docx', "
              "1704067200, 20480, 0, 1)")
    db.commit()
    db.close()
    return root


def build_no_gdrive(root: Path) -> Path:
    (root / "unrelated").mkdir(parents=True)
    return root
