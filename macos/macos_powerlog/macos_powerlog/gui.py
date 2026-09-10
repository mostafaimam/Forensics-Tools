"""Graphical viewer for macos_powerlog."""

from __future__ import annotations

from pathlib import Path

from macos_powerlog import flags as _flags
from macos_powerlog.cli import _discover
from macos_powerlog.parse import collect

_COLS = ["timestamp", "kind", "value", "detail", "latitude", "longitude",
         "table", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_powerlog.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for e in collect(str(db)).events:
                    r = e.row()
                    r["severity"] = _flags.severity(e.notable)
                    rows.append(r)
        return rows

    return run("macos_powerlog - PowerLog timeline", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open CurrentPowerlog.PLSQL", multi=True,
               alert_keys=("notable",))
