"""Graphical viewer for browser_downloads (see ``browser_downloads --gui``)."""

from __future__ import annotations

from browser_downloads.analyze import analyze
from browser_downloads.output import row

_COLS = ["start_time", "browser", "filename", "received_bytes", "total_bytes",
         "state", "on_disk", "zone_id", "url", "referrer", "target_path",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_downloads.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(d) for d in res.downloads]

    return run("browser_downloads - downloads + disk correlation", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open History / places.sqlite / folder", multi=True,
               alert_keys=("notable",))
