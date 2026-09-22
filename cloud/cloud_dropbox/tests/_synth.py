"""Build synthetic Dropbox client database files."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def build_tree(root: Path) -> Path:
    instance = root / "Dropbox" / "instance1"
    instance.mkdir(parents=True)

    config = sqlite3.connect(instance / "config.dbx")
    config.execute("CREATE TABLE config (key TEXT, value TEXT)")
    config.execute("INSERT INTO config VALUES ('email', 'alice@example.com')")
    config.execute("INSERT INTO config VALUES ('host_id', 'abc123')")
    config.commit()
    config.close()

    cache = sqlite3.connect(instance / "filecache.dbx")
    cache.execute("CREATE TABLE file_journal (server_path TEXT, "
                 "local_filename TEXT, local_mtime TEXT, local_size "
                 "INTEGER)")
    cache.execute("INSERT INTO file_journal VALUES "
                 "('/Docs/report.docx', 'report.docx', "
                 "'2026-01-01T00:00:00Z', 40960)")
    cache.commit()
    cache.close()

    encrypted = instance / "deleted.dbx"
    encrypted.write_bytes(os.urandom(200))   # SQLCipher-shaped: no magic
    return root


def build_no_dropbox(root: Path) -> Path:
    (root / "unrelated").mkdir(parents=True)
    return root
