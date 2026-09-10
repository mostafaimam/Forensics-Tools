"""Graphical viewer for windows_shellbags (see ``windows_shellbags --gui``)."""

from __future__ import annotations

from windows_shellbags.analyze import analyze
from windows_shellbags.output import row

_COLS = ["path", "item_type", "depth", "mru_position", "last_interacted",
         "created", "modified", "accessed", "mft_entry", "node_slot",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_shellbags.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(b) for b in analyze([str(p)]).bags]
        return rows

    return run("windows_shellbags - folder access tree", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a mounted-image root or hive", multi=True,
               open_is_dir=True, alert_keys=("notable",))
