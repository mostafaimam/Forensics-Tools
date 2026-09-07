"""Chromium-family ``History`` store (Chrome / Edge / Brave / Opera / Vivaldi)."""

from __future__ import annotations

from pathlib import Path

from browser_history import timeconv as _t
from browser_history.dbopen import connect, has_table, query
from browser_history.model import Download, SearchTerm, Visit

_CORE_TRANSITION = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "subframe", 4: "subframe",
    5: "generated", 6: "auto_toplevel", 7: "form_submit", 8: "reload",
    9: "keyword", 10: "keyword_generated",
}
_TRANS_LABEL = {
    "link": "link", "typed": "typed", "auto_bookmark": "bookmark",
    "subframe": "subframe", "generated": "generated",
    "auto_toplevel": "start-page", "form_submit": "form-submit",
    "reload": "reload", "keyword": "keyword", "keyword_generated": "keyword",
}
_DOWNLOAD_STATE = {0: "in-progress", 1: "complete", 2: "cancelled",
                   3: "interrupted", 4: "interrupted"}
_DANGER = {0: "not_dangerous", 1: "dangerous-file", 2: "dangerous-url",
           3: "dangerous-content", 4: "maybe-dangerous-content",
           5: "uncommon-content", 6: "user-validated", 7: "dangerous-host",
           8: "potentially-unwanted", 10: "async-scanning",
           13: "blocked-too-large", 20: "sensitive-content-warning"}


def looks_like(path: Path) -> bool:
    return path.name in ("History", "History.db") or path.suffix == ""


def _redirect(qualifiers: int) -> bool:
    # CHAIN_START/END and CLIENT/SERVER_REDIRECT live in the top bits
    return bool(qualifiers & 0xC0000000)


def parse(db_path: str, browser: str, profile: str) -> list:
    out: list = []
    p = str(db_path)
    with connect(p) as con:
        if not has_table(con, "urls"):
            return out
        urls = {r["id"]: r for r in query(
            con, "SELECT id, url, title, visit_count, typed_count FROM urls")}

        if has_table(con, "visits"):
            rows = query(con,
                         "SELECT url, visit_time, from_visit, transition "
                         "FROM visits ORDER BY visit_time")
            id2url = {i: r["url"] for i, r in urls.items()}
            visit_by_id = {}
            for r in query(con, "SELECT id, url FROM visits"):
                visit_by_id[r["id"]] = id2url.get(r["url"], "")
            for r in rows:
                u = urls.get(r["url"])
                if not u:
                    continue
                trans = int(r["transition"] or 0)
                core = _CORE_TRANSITION.get(trans & 0xFF, "link")
                label = _TRANS_LABEL.get(core, core)
                if _redirect(trans) and label == "link":
                    label = "redirect"
                out.append(Visit(
                    browser=browser, profile=profile, url=u["url"],
                    title=u["title"] or "",
                    visit_time=_t.chrome(r["visit_time"]),
                    visit_count=u["visit_count"] or 0,
                    typed=core in ("typed", "keyword", "keyword_generated"),
                    transition=label,
                    from_url=visit_by_id.get(r["from_visit"], ""),
                    source_db=p))
        else:
            for u in urls.values():
                out.append(Visit(
                    browser=browser, profile=profile, url=u["url"],
                    title=u["title"] or "", visit_time="",
                    visit_count=u["visit_count"] or 0,
                    typed=bool(u["typed_count"]), transition="link",
                    source_db=p))

        if has_table(con, "keyword_search_terms"):
            for r in query(con,
                           "SELECT k.term AS term, u.url AS url, "
                           "u.last_visit_time AS t "
                           "FROM keyword_search_terms k JOIN urls u "
                           "ON u.id = k.url_id"):
                out.append(SearchTerm(
                    browser=browser, profile=profile, term=r["term"] or "",
                    url=r["url"] or "", time=_t.chrome(r["t"]), source_db=p))

        if has_table(con, "downloads"):
            chains = {}
            if has_table(con, "downloads_url_chains"):
                for r in query(con, "SELECT id, chain_index, url "
                               "FROM downloads_url_chains ORDER BY id, "
                               "chain_index"):
                    chains.setdefault(r["id"], []).append(r["url"])
            for r in query(con, "SELECT * FROM downloads"):
                d = dict(r)
                url = (chains.get(d.get("id"), [""])[0]
                       or d.get("url") or d.get("tab_url") or "")
                out.append(Download(
                    browser=browser, profile=profile, url=url,
                    referrer=d.get("referrer", "") or "",
                    tab_url=d.get("tab_url", "") or "",
                    target_path=d.get("target_path")
                    or d.get("current_path", "") or "",
                    start_time=_t.chrome(d.get("start_time")),
                    end_time=_t.chrome(d.get("end_time")),
                    bytes=d.get("received_bytes") or 0,
                    total_bytes=d.get("total_bytes") or 0,
                    state=_DOWNLOAD_STATE.get(d.get("state"), str(d.get("state"))),
                    danger=_DANGER.get(d.get("danger_type"),
                                       str(d.get("danger_type", ""))),
                    mime=d.get("mime_type", "") or "", source_db=p))
    return out
