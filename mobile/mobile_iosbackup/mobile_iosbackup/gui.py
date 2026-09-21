"""Graphical viewer for mobile_iosbackup."""

from __future__ import annotations

from mobile_iosbackup.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from mobile_iosbackup.collect import collect
    from mobile_iosbackup.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("mobile_iosbackup - iOS backup file inventory", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a backup folder",
               open_is_dir=True, multi=True,
               alert_keys=("file_id_mismatch",))
