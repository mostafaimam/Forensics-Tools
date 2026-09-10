"""Graphical viewer for windows_sdb."""

from __future__ import annotations

_COLS = ["kind", "name", "detail", "guid", "time", "dll",
         "matching_files", "shims", "patches", "layers", "severity",
         "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_sdb.collect import collect
    from windows_sdb.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_sdb - shim database", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open .sdb / folder", open_is_dir=True,
               multi=True, alert_keys=("notable",))
