"""Graphical viewer for cloud_onedrive."""

from __future__ import annotations

from cloud_onedrive.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_onedrive.collect import collect
    from cloud_onedrive.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_onedrive - OneDrive settings / sync-DB viewer", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a OneDrive folder / file",
              open_is_dir=True, multi=True)
