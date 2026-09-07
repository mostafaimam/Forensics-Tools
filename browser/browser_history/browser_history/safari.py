"""Safari ``History.db`` (macOS / iOS)."""

from __future__ import annotations

from pathlib import Path

from browser_history import timeconv as _t
from browser_history.dbopen import connect, has_table, query
from browser_history.model import Visit


def looks_like(path: Path) -> bool:
    return path.name == "History.db"


def parse(db_path: str, browser: str, profile: str) -> list:
    out: list = []
    p = str(db_path)
    with connect(p) as con:
        if not (has_table(con, "history_items")
                and has_table(con, "history_visits")):
            return out
        items = {r["id"]: r for r in query(
            con, "SELECT id, url, visit_count FROM history_items")}
        by_visit = {r["id"]: r["history_item"] for r in query(
            con, "SELECT id, history_item FROM history_visits")}
        for r in query(con,
                       "SELECT history_item, visit_time, title, "
                       "redirect_source, redirect_destination "
                       "FROM history_visits ORDER BY visit_time"):
            it = items.get(r["history_item"])
            if not it:
                continue
            label = "link"
            if r["redirect_destination"] is not None:
                label = "redirect"
            frm = items.get(by_visit.get(r["redirect_source"]))
            out.append(Visit(
                browser=browser, profile=profile, url=it["url"],
                title=r["title"] or "",
                visit_time=_t.cocoa(r["visit_time"]),
                visit_count=it["visit_count"] or 0,
                typed=False, transition=label,
                from_url=frm["url"] if frm else "", source_db=p))
    return out
