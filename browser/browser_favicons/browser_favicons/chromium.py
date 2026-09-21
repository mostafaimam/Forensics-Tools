"""Chromium ``Favicons`` database reader."""

from __future__ import annotations

from browser_favicons.dbopen import connect, query, table_columns
from browser_favicons.timeconv import chrome

_ICON_TYPES = {1: "favicon", 2: "touch_icon", 4: "touch_precomposed_icon",
              8: "web_manifest_icon"}


def _icon_type_label(v) -> str:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    labels = [name for bit, name in _ICON_TYPES.items() if v & bit]
    return "+".join(labels) if labels else str(v)


def read(path: str) -> list[dict]:
    rows = []
    with connect(path) as con:
        fb_cols = table_columns(con, "favicon_bitmaps")
        if not fb_cols or not table_columns(con, "favicons") or \
                not table_columns(con, "icon_mapping"):
            return rows
        want = [c for c in ("image_data", "width", "height",
                            "last_updated", "last_requested")
               if c in fb_cols]
        sql = (f"SELECT icon_mapping.page_url AS page_url, "
              f"favicons.url AS icon_url, favicons.icon_type AS icon_type"
              + "".join(f", favicon_bitmaps.{c} AS {c}" for c in want)
              + " FROM icon_mapping "
              "JOIN favicons ON icon_mapping.icon_id = favicons.id "
              "JOIN favicon_bitmaps ON favicon_bitmaps.icon_id = "
              "favicons.id")
        for r in query(con, sql):
            rows.append({
                "browser": "chromium",
                "page_url": r["page_url"],
                "icon_url": r["icon_url"],
                "icon_type": _icon_type_label(r["icon_type"]),
                "width": r["width"] if "width" in want else "",
                "height": r["height"] if "height" in want else "",
                "last_updated": (chrome(r["last_updated"])
                                if "last_updated" in want else ""),
                "image_data": (r["image_data"]
                              if "image_data" in want else None),
            })
    return rows
