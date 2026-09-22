"""Graphical viewer for cloud_box."""

from __future__ import annotations

from cloud_box.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_box.collect import collect
    from cloud_box.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_box - Box Drive metadata viewer", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a Box folder / file",
              open_is_dir=True, multi=True)
