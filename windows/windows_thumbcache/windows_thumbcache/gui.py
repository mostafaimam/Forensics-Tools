"""Graphical viewer for windows_thumbcache (see ``windows_thumbcache --gui``)."""

from __future__ import annotations

from windows_thumbcache.analyze import analyze
from windows_thumbcache.cli import _severity

_COLS = ["cache_id", "identifier", "format", "width", "height", "data_size",
         "db", "last_modified", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_thumbcache.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for t in analyze([str(p)]).thumbnails:
                r = t.row()
                r["severity"] = _severity(t.notable)
                rows.append(r)
        return rows

    return run("windows_thumbcache - Explorer thumbnails", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a thumbcache_*.db or folder", multi=True,
               alert_keys=("notable",))
