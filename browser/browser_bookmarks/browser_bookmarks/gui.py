"""Graphical viewer for browser_bookmarks (see ``browser_bookmarks --gui``)."""

from __future__ import annotations

from browser_bookmarks.analyze import analyze
from browser_bookmarks.output import row

_COLS = ["date_added", "date_modified", "browser", "folder", "title", "url",
         "source", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_bookmarks.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(b) for b in res.bookmarks]

    return run("browser_bookmarks - bookmark tree", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Bookmarks / places.sqlite / folder", multi=True,
               alert_keys=("notable",))
