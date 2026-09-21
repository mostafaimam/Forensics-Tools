"""Optional cross-reference: is this favicon's page URL still in History?"""

from __future__ import annotations

from browser_favicons.dbopen import connect, has_table, query


def load_history_urls(path: str) -> set[str] | None:
    with connect(path) as con:
        if has_table(con, "urls"):
            return {r["url"] for r in query(con, "SELECT url FROM urls")}
        if has_table(con, "moz_places"):
            return {r["url"] for r in query(con, "SELECT url FROM moz_places")}
    return None
