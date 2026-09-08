"""Chromium-family download history (History database)."""

from __future__ import annotations

from pathlib import Path

from browser_downloads import timeconv as _t
from browser_downloads.dbopen import connect, has_table, query, table_columns
from browser_downloads.model import Download

_STATE = {0: "in-progress", 1: "complete", 2: "cancelled", 3: "interrupted",
          4: "interrupted"}
_DANGER = {0: "not-dangerous", 1: "dangerous-file", 2: "dangerous-url",
           3: "dangerous-content", 4: "maybe-dangerous-content",
           5: "uncommon-content", 6: "user-validated", 7: "dangerous-host",
           8: "potentially-unwanted", 9: "allowlisted-by-policy",
           10: "async-scanning", 11: "blocked-password-protected",
           12: "blocked-too-large", 13: "sensitive-content-warning",
           14: "sensitive-content-block", 15: "deep-scanned-safe",
           16: "deep-scanned-opened-dangerous", 17: "prompt-for-scanning",
           20: "blocked-unsupported-filetype"}
_INTERRUPT = {0: "", 1: "file-failed", 3: "file-no-space", 5: "file-name-too-long",
              6: "file-too-large", 7: "file-virus-infected",
              10: "file-blocked", 11: "file-security-check-failed",
              20: "network-failed", 21: "network-timeout",
              22: "network-disconnected", 23: "network-server-down",
              33: "network-invalid-request", 30: "server-failed",
              31: "server-no-range", 33: "server-bad-content",
              35: "server-unauthorized", 36: "server-cert-problem",
              40: "user-cancelled", 41: "user-shutdown", 50: "crash"}

_CHROMIUM_DIRS = ("Chrome", "Chromium", "Edge", "BraveSoftware", "Opera",
                  "Opera Software", "Vivaldi", "Chrome Beta", "Chrome Dev")


def _browser_from_path(p: str) -> str:
    s = p.replace("\\", "/").lower()
    if "brave" in s:
        return "Brave"
    if "/edge/" in s or "microsoft/edge" in s:
        return "Edge"
    if "opera" in s:
        return "Opera"
    if "vivaldi" in s:
        return "Vivaldi"
    if "chromium" in s:
        return "Chromium"
    return "Chrome"


def _profile_from_path(p: str) -> str:
    parts = Path(p).parts
    for seg in reversed(parts[:-1]):
        if seg.lower().startswith(("profile", "default")) or seg == "Default":
            return seg
    return ""


def parse(db_path: str) -> list[Download]:
    out: list[Download] = []
    p = str(db_path)
    browser = _browser_from_path(p)
    profile = _profile_from_path(p)
    with connect(p) as con:
        if not has_table(con, "downloads"):
            return out
        cols = table_columns(con, "downloads")
        chains: dict = {}
        if has_table(con, "downloads_url_chains"):
            for r in query(con, "SELECT id, chain_index, url FROM "
                           "downloads_url_chains ORDER BY id, chain_index"):
                chains.setdefault(r["id"], []).append(r["url"])
        for r in query(con, "SELECT * FROM downloads"):
            d = dict(r)
            chain = chains.get(d.get("id"), [])
            url = (chain[0] if chain else "") or d.get("tab_url", "") or ""
            out.append(Download(
                browser=browser, profile=profile, source="history-db",
                url=url,
                referrer=d.get("referrer", "") or "",
                tab_url=d.get("tab_url", "") or "",
                target_path=d.get("target_path")
                or d.get("current_path", "") or "",
                start_time=_t.chrome(d.get("start_time")),
                end_time=_t.chrome(d.get("end_time")),
                received_bytes=d.get("received_bytes") or 0,
                total_bytes=d.get("total_bytes") or 0,
                state=_STATE.get(d.get("state"), str(d.get("state", ""))),
                danger=_DANGER.get(d.get("danger_type"),
                                   str(d.get("danger_type", ""))),
                interrupt=_INTERRUPT.get(d.get("interrupt_reason"), "")
                if "interrupt_reason" in cols else "",
                mime=d.get("mime_type", "")
                or d.get("original_mime_type", "") or "",
                opened=_t.chrome(d.get("last_access_time"))
                if d.get("opened") else "",
                source_db=p))
    return out
