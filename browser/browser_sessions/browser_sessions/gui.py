"""Graphical viewer for browser_sessions (see ``browser_sessions --gui``)."""

from __future__ import annotations

from browser_sessions.analyze import analyze
from browser_sessions.output import row

_COLS = ["last_accessed", "browser", "window", "index", "pinned", "closed",
         "current_title", "current_url", "entry_count", "has_formdata",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_sessions.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(t) for t in res.tabs]

    return run("browser_sessions - tabs at last close", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open session file / folder", multi=True,
               alert_keys=("notable",))
