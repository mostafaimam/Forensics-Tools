"""Graphical viewer for windows_notifications."""

from __future__ import annotations

from pathlib import Path

from windows_notifications import flags as _flags
from windows_notifications.cli import _discover
from windows_notifications.parse import parse

_COLS = ["arrival", "expiry", "app", "type", "text", "tag", "group",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_notifications.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for n in parse(str(db)):
                    r = n.row()
                    r["severity"] = _flags.severity(n.notable)
                    rows.append(r)
        return rows

    return run("windows_notifications - toast history", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open wpndatabase.db", multi=True,
               alert_keys=("notable",))
