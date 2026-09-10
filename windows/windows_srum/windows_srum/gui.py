"""Graphical viewer for windows_srum (see ``windows_srum --gui``)."""

from __future__ import annotations

from windows_srum.analyze import analyze
from windows_srum.output import row

_COLS = ["provider", "timestamp", "app", "user", "bytes_sent", "bytes_recvd",
         "connected_seconds", "fg_cycle_time", "bg_cycle_time", "severity",
         "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_srum.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(r) for r in analyze([str(p)]).rows]
        return rows

    return run("windows_srum - resource usage timeline", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open SRUDB.dat", multi=True, alert_keys=("notable",))
