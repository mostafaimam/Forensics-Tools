"""Build a synthetic OneDrive settings tree + SQLite sync database."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def build_tree(root: Path) -> Path:
    settings = root / "Microsoft" / "OneDrive" / "settings" / "Personal"
    settings.mkdir(parents=True)
    (settings / "global.ini").write_text(
        "cid = 1234567890ABCDEF\n"
        "EmailAddress = alice@example.com\n"
        "; a comment line\n"
        "DisplayName: Alice Example\n", encoding="utf-8")

    db_path = settings / "SyncEngineDatabase.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE items (ItemId TEXT, Path TEXT, "
               "LastModifiedTime TEXT, Size INTEGER)")
    con.execute("INSERT INTO items VALUES ('i1', 'Documents/report.docx', "
               "'2026-01-01T00:00:00Z', 40960)")
    con.execute("INSERT INTO items VALUES ('i2', 'Pictures/photo.jpg', "
               "'2026-01-02T00:00:00Z', 204800)")
    con.commit()
    con.close()
    return root


def build_ese_stub(root: Path) -> Path:
    settings = root / "Microsoft" / "OneDrive" / "settings" / "Business1"
    settings.mkdir(parents=True)
    db_path = settings / "SyncEngineDatabase.db"
    db_path.write_bytes(b"\x00\x01\x00\x00" + b"\xef\xcd\xab\x89" +
                        b"\x00" * 100)
    return root
