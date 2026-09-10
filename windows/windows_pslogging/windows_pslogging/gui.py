"""Graphical viewer for windows_pslogging."""

from __future__ import annotations

from windows_pslogging import flags as _flags
from windows_pslogging.collect import collect

_COLS = ["time", "kind", "event_id", "computer", "user", "host_app",
         "fragments", "decoded", "text", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_pslogging.guikit import run

    def load(ps):
        rows = []
        for sc in collect([str(p) for p in ps]).scripts:
            r = sc.row()
            r["severity"] = _flags.severity(sc.notable)
            rows.append(r)
        return rows

    return run("windows_pslogging - PowerShell activity", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open EVTX / transcript / dir", multi=True,
               open_is_dir=True, alert_keys=("notable",))
