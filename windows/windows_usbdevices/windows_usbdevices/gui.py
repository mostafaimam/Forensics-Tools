"""Graphical viewer for windows_usbdevices."""

from __future__ import annotations

from windows_usbdevices.analyze import analyze
from windows_usbdevices.cli import _severity

_COLS = ["first_connected", "last_arrival", "last_removal", "vendor",
         "product", "serial", "friendly_name", "volume_name",
         "drive_letters", "vid", "pid", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_usbdevices.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for d in analyze([str(p)]).devices:
                r = d.row()
                r["severity"] = _severity(d.notable)
                rows.append(r)
        return rows

    return run("windows_usbdevices - removable-device history", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a mounted root or SYSTEM hive", multi=True,
               alert_keys=("notable",))
