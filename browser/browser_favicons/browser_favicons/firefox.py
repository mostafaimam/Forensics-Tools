"""Firefox ``favicons.sqlite`` reader (modern moz_icons schema, FF55+)."""

from __future__ import annotations

from browser_favicons.dbopen import connect, query, table_columns
from browser_favicons.timeconv import unix_ms


def read(path: str) -> list[dict]:
    rows = []
    with connect(path) as con:
        icon_cols = table_columns(con, "moz_icons")
        if not icon_cols or not table_columns(con, "moz_pages_w_icons") \
                or not table_columns(con, "moz_icons_to_pages"):
            return rows
        want = [c for c in ("data", "width", "color") if c in icon_cols]
        sql = (f"SELECT p.page_url AS page_url, i.icon_url AS icon_url, "
              f"itp.expire_ms AS expire_ms"
              + "".join(f", i.{c} AS {c}" for c in want)
              + " FROM moz_icons_to_pages itp "
              "JOIN moz_pages_w_icons p ON p.id = itp.page_id "
              "JOIN moz_icons i ON i.id = itp.icon_id")
        for r in query(con, sql):
            rows.append({
                "browser": "firefox",
                "page_url": r["page_url"],
                "icon_url": r["icon_url"],
                "icon_type": "favicon",
                "width": r["width"] if "width" in want else "",
                "height": r["width"] if "width" in want else "",
                "last_updated": unix_ms(r["expire_ms"]),
                "image_data": r["data"] if "data" in want else None,
            })
    return rows
