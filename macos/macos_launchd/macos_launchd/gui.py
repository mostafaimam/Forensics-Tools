"""Graphical viewer for macos_launchd."""

from __future__ import annotations

from macos_launchd import flags as _flags
from macos_launchd.collect import collect, sort_jobs

_COLS = ["scope", "label", "program", "command_line", "run_as", "disabled",
         "run_at_load", "keep_alive", "triggers", "env", "world_writable",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_launchd.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            res = collect(str(p))
            sort_jobs(res.jobs)
            for j in res.jobs:
                r = j.row()
                r["severity"] = _flags.severity(j.notable)
                rows.append(r)
        return rows

    return run("macos_launchd - launchd persistence", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a macOS volume or plist", multi=True,
               open_is_dir=True, alert_keys=("notable",))
