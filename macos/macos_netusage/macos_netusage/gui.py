"""Graphical viewer for macos_netusage."""

from __future__ import annotations

from pathlib import Path

from macos_netusage import flags as _flags
from macos_netusage.cli import _discover
from macos_netusage.parse import parse

_COLS = ["process", "bundle", "first_seen", "last_seen", "total_out",
         "total_in", "wifi_out", "wwan_out", "wired_out", "rows",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_netusage.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for pu in parse(str(db)).processes:
                    r = pu.row()
                    r["severity"] = _flags.severity(pu.notable)
                    rows.append(r)
        return rows

    return run("macos_netusage - per-process network bytes", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open netusage.sqlite", multi=True,
               alert_keys=("notable",))
