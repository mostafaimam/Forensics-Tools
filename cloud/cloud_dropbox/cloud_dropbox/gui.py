"""Graphical viewer for cloud_dropbox."""

from __future__ import annotations

from cloud_dropbox.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_dropbox.collect import collect
    from cloud_dropbox.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_dropbox - Dropbox sync-DB viewer", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a Dropbox folder / file",
              open_is_dir=True, multi=True)
