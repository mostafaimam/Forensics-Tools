"""Build a synthetic Box Drive-shaped SQLite database."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def build_tree(root: Path) -> Path:
    box = root / "Box" / "Box" / "data"
    box.mkdir(parents=True)

    db = sqlite3.connect(box / "sync_state.db")
    db.execute("CREATE TABLE synced_items (item_id TEXT, name TEXT, "
              "parent_id TEXT, modified_at TEXT, size INTEGER, "
              "offline INTEGER)")
    db.execute("INSERT INTO synced_items VALUES ('101', 'budget.xlsx', "
              "'0', '2026-01-01T00:00:00Z', 51200, 1)")
    db.commit()
    db.close()

    # a non-sqlite candidate the same name pattern would pick up
    (box / "cache.dat").write_bytes(os.urandom(50))
    return root


def build_no_box(root: Path) -> Path:
    (root / "unrelated" / "notabox.db").parent.mkdir(parents=True)
    return root
