"""Graphical viewer for windows_webcache (see ``windows_webcache --gui``)."""

from __future__ import annotations

from windows_webcache.analyze import analyze
from windows_webcache.output import row

_COLS = ["container", "entry_type", "url", "filename", "size", "access_count",
         "modified", "accessed", "expiry", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_webcache.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(e) for e in analyze([str(p)]).entries]
        return rows

    return run("windows_webcache - WinINET store", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open WebCacheV01.dat", multi=True,
               alert_keys=("notable",))
