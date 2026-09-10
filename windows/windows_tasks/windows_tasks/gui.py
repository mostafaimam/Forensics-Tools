"""Graphical viewer for windows_tasks (see ``windows_tasks --gui``)."""

from __future__ import annotations

from windows_tasks.analyze import analyze
from windows_tasks.output import row

_COLS = ["name", "task_path", "enabled", "hidden", "author", "registered",
         "last_run", "run_as", "run_level", "triggers", "command_line",
         "registry_only", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_tasks.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(t) for t in analyze([str(p)]).tasks]
        return rows

    return run("windows_tasks - Scheduled Tasks", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a mounted-image root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
