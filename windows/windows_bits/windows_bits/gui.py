"""Graphical viewer for windows_bits."""

from __future__ import annotations

_COLS = ["ctime", "mtime", "type", "state", "job_name", "owner", "url",
         "dest", "download_size", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_bits.collect import collect
    from windows_bits.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_bits - BITS transfer history", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open qmgr*.dat / qmgr.db / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
