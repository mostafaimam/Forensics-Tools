"""Graphical viewer for macos_fsevents."""

from __future__ import annotations

from macos_fsevents.collect import collect
from macos_fsevents.cli import _severity

_COLS = ["approx_time", "path", "flags", "event_id", "node_id",
         "dls_version", "source_file", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_fsevents.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for rec in collect(str(p)).records:
                r = rec.row()
                r["severity"] = _severity(rec.notable)
                rows.append(r)
        return rows

    return run("macos_fsevents - file-system changes", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a macOS volume or .fseventsd log", multi=True,
               open_is_dir=True, alert_keys=("notable",))
