"""Graphical viewer for macos_bt."""

from __future__ import annotations

from pathlib import Path

from macos_bt import flags as _flags
from macos_bt.cli import _discover
from macos_bt.parse import parse


_COLS = ["mac", "name", "is_paired", "is_hid", "device_type", "device_minor",
         "manufacturer", "battery", "last_inquiry_update",
         "last_services_update", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_bt.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for pl in _discover(Path(p)):
                for d in parse(pl.read_bytes(), str(pl)):
                    r = d.row()
                    r["severity"] = _flags.severity(d.notable)
                    rows.append(r)
        return rows

    return run("macos_bt - Bluetooth devices", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open com.apple.Bluetooth.plist", multi=True,
               alert_keys=("notable",))
