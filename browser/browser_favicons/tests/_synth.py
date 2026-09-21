"""Build real SQLite stores matching the favicon schemas."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20

_CHROME_EPOCH_SAMPLE = 13385952000000000  # ~2025-03-09 chrome-epoch us


def build_chromium_favicons(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE favicons (id INTEGER PRIMARY KEY, url "
               "LONGVARCHAR NOT NULL, icon_type INTEGER DEFAULT 1)")
    con.execute("CREATE TABLE favicon_bitmaps (id INTEGER PRIMARY KEY, "
               "icon_id INTEGER NOT NULL, last_updated INTEGER DEFAULT 0, "
               "image_data BLOB, width INTEGER DEFAULT 0, "
               "height INTEGER DEFAULT 0, last_requested INTEGER DEFAULT 0)")
    con.execute("CREATE TABLE icon_mapping (id INTEGER PRIMARY KEY, "
               "page_url LONGVARCHAR NOT NULL, icon_id INTEGER)")
    con.execute("INSERT INTO favicons VALUES (1, 'https://a.example/f.ico', 1)")
    con.execute("INSERT INTO favicon_bitmaps VALUES "
               "(1, 1, ?, ?, 16, 16, 0)", (_CHROME_EPOCH_SAMPLE, _PNG_MAGIC))
    con.execute("INSERT INTO icon_mapping VALUES "
               "(1, 'https://a.example/page', 1)")
    con.execute("INSERT INTO favicons VALUES "
               "(2, 'https://cleared.example/f.ico', 1)")
    con.execute("INSERT INTO favicon_bitmaps VALUES "
               "(2, 2, ?, ?, 32, 32, 0)", (_CHROME_EPOCH_SAMPLE, _PNG_MAGIC))
    con.execute("INSERT INTO icon_mapping VALUES "
               "(2, 'https://cleared.example/gone', 2)")
    con.commit()
    con.close()


def build_chromium_history(path: Path, urls: list[str]) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url "
               "LONGVARCHAR)")
    for u in urls:
        con.execute("INSERT INTO urls (url) VALUES (?)", (u,))
    con.commit()
    con.close()


def build_firefox_favicons(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE moz_icons (id INTEGER PRIMARY KEY, "
               "icon_url TEXT, fixed_icon_url_hash INTEGER, width INTEGER, "
               "root BOOLEAN, color BLOB, expire_ms INTEGER, data BLOB)")
    con.execute("CREATE TABLE moz_pages_w_icons (id INTEGER PRIMARY KEY, "
               "page_url TEXT, page_url_hash INTEGER)")
    con.execute("CREATE TABLE moz_icons_to_pages (page_id INTEGER, "
               "icon_id INTEGER, expire_ms INTEGER)")
    con.execute("INSERT INTO moz_icons VALUES "
               "(1, 'https://ff.example/icon.png', 0, 32, 0, NULL, "
               "1770000000000, ?)", (_PNG_MAGIC,))
    con.execute("INSERT INTO moz_pages_w_icons VALUES "
               "(1, 'https://ff.example/page', 0)")
    con.execute("INSERT INTO moz_icons_to_pages VALUES "
               "(1, 1, 1770000000000)")
    con.commit()
    con.close()
