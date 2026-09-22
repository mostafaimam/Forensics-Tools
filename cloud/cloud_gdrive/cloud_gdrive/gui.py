"""Graphical viewer for cloud_gdrive."""

from __future__ import annotations

from cloud_gdrive.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_gdrive.collect import collect
    from cloud_gdrive.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_gdrive - Google Drive for Desktop sync-DB viewer",
              load, columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a DriveFS folder / file",
              open_is_dir=True, multi=True)
