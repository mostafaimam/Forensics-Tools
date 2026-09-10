"""Graphical viewer for windows_logfile."""

from __future__ import annotations

_COLS = ["lsn", "action", "name", "mft", "parent_mft", "namespace",
         "created", "modified", "real_size", "redo_op", "severity",
         "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_logfile.collect import collect
    from windows_logfile.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_logfile - NTFS $LogFile events", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open $LogFile / folder", open_is_dir=True,
               multi=True, alert_keys=("notable",))
