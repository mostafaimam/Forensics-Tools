"""Build real SQLite stores matching the Chromium schemas."""

from __future__ import annotations

import sqlite3
from pathlib import Path

# microseconds since 1601-01-01 for 2026-01-15 00:00:00 UTC (approx)
_CHROME_EPOCH_SAMPLE = 13385952000000000


def build_shortcuts(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE omni_box_shortcuts (
        id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR,
        url VARCHAR, contents VARCHAR, contents_class VARCHAR,
        description VARCHAR, description_class VARCHAR, transition INTEGER,
        type INTEGER, keyword VARCHAR, last_access_time INTEGER,
        number_of_hits INTEGER)""")
    con.execute("INSERT INTO omni_box_shortcuts VALUES "
               "('s1','gmail','gmail.com','https://mail.google.com/',"
               "'Gmail','','','',0,0,'',?,42)", (_CHROME_EPOCH_SAMPLE,))
    con.execute("INSERT INTO omni_box_shortcuts VALUES "
               "('s2','192.168.1.1','http://192.168.1.1/',"
               "'http://192.168.1.1/','Router admin','','','',0,0,'',?,3)",
               (_CHROME_EPOCH_SAMPLE,))
    con.commit()
    con.close()


def build_top_sites(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE top_sites (
        url VARCHAR PRIMARY KEY, url_rank INTEGER, title VARCHAR,
        redirects VARCHAR, last_forced INTEGER)""")
    con.execute("INSERT INTO top_sites VALUES "
               "('https://news.example.com/', 0, 'Example News', '', 0)")
    con.execute("INSERT INTO top_sites VALUES "
               "('javascript:alert(1)', 1, 'evil bookmarklet', '', 0)")
    con.commit()
    con.close()


def build_predictor(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE network_action_predictor (
        id VARCHAR PRIMARY KEY, user_text VARCHAR, url VARCHAR,
        number_of_hits INTEGER, number_of_misses INTEGER)""")
    con.execute("INSERT INTO network_action_predictor VALUES "
               "('p1','exa','https://example.com/',9,1)")
    con.commit()
    con.close()


def build_profile(root: Path) -> Path:
    profile = root / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    build_shortcuts(profile / "Shortcuts")
    build_top_sites(profile / "Top Sites")
    build_predictor(profile / "Network Action Predictor")
    return profile
