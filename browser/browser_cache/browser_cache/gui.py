"""Graphical viewer for browser_cache (see ``browser_cache --gui``)."""

from __future__ import annotations

from browser_cache.analyze import analyze
from browser_cache.output import row

_COLS = ["response_time", "last_fetched", "browser", "cache", "status", "url",
         "content_type", "content_encoding", "body_size", "server",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_cache.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(e) for e in res.entries]

    return run("browser_cache - cached HTTP responses", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Cache / cache2 directory", multi=True,
               alert_keys=("notable",))
