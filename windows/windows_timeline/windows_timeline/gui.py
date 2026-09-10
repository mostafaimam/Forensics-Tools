"""Graphical viewer for windows_timeline (see ``windows_timeline --gui``)."""

from __future__ import annotations

from pathlib import Path

from windows_timeline import flags as _flags
from windows_timeline.cli import _discover
from windows_timeline.parse import parse

_COLS = ["start", "end", "activity_type", "app", "display_text",
         "content_uri", "duration_s", "clipboard_text", "from_operation",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_timeline.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for act in parse(str(db)):
                    r = act.row()
                    r["severity"] = _flags.severity(act.notable)
                    rows.append(r)
        return rows

    return run("windows_timeline - Activity History", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open ActivitiesCache.db", multi=True,
               alert_keys=("notable",))
