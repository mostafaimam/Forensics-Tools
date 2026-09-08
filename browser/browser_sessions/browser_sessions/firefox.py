"""Parse Firefox ``sessionstore.jsonlz4`` (mozLz4 + JSON)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from browser_sessions.lz4 import Lz4Error, mozlz4_decompress
from browser_sessions.model import Tab


def _profile(p: str) -> str:
    for seg in reversed(Path(p).parts[:-1]):
        low = seg.lower()
        if ".default" in low or "profile" in low:
            return seg
    return ""


def _ms(v) -> str:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return datetime.fromtimestamp(v / 1000, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _load(path: str) -> dict | None:
    raw = Path(path).read_bytes()
    try:
        if raw[:4] == b"moz\x4c" or raw[:3] == b"moz":
            raw = mozlz4_decompress(raw)
    except Lz4Error:
        pass
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


def _tabs_from_window(win: dict, br: str, pr: str, fname: str, wi: int,
                      closed: bool) -> list[Tab]:
    out: list[Tab] = []
    for ti, tab in enumerate(win.get("tabs", []) or []):
        entries = tab.get("entries", []) or []
        cur_i = tab.get("index", len(entries)) - 1
        cur_i = max(0, min(cur_i, len(entries) - 1)) if entries else 0
        t = Tab(browser=br, profile=pr, source_file=fname,
                window=f"window {wi + 1}", index=ti,
                pinned=bool(tab.get("pinned")),
                group=str(tab.get("groupId", "") or ""),
                closed=closed,
                entry_count=len(entries),
                last_accessed=_ms(tab.get("lastAccessed")),
                history=[(e.get("url", ""), e.get("title", ""))
                         for e in entries],
                has_formdata=bool(tab.get("formdata")))
        if entries:
            e = entries[cur_i]
            t.current_url = e.get("url", "")
            t.current_title = e.get("title", "")
        out.append(t)
    # recently-closed tabs recorded on the window
    for ct in win.get("_closedTabs", []) or []:
        state = ct.get("state", ct)
        entries = state.get("entries", []) or []
        t = Tab(browser=br, profile=pr, source_file=fname,
                window=f"window {wi + 1}", closed=True,
                entry_count=len(entries),
                last_accessed=_ms(ct.get("closedAt")),
                history=[(e.get("url", ""), e.get("title", ""))
                         for e in entries],
                has_formdata=bool(state.get("formdata")))
        if entries:
            t.current_url = entries[-1].get("url", "")
            t.current_title = entries[-1].get("title", "")
        out.append(t)
    return out


def parse(path: str) -> list[Tab]:
    p = str(path)
    data = _load(p)
    if not data:
        return []
    br, pr = "Firefox", _profile(p)
    fname = Path(p).name
    out: list[Tab] = []
    for wi, win in enumerate(data.get("windows", []) or []):
        out += _tabs_from_window(win, br, pr, fname, wi, closed=False)
    for wi, win in enumerate(data.get("_closedWindows", []) or []):
        out += _tabs_from_window(win, br, pr, fname, wi, closed=True)
    return out
