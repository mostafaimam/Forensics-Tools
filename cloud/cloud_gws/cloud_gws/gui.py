"""Graphical viewer for cloud_gws."""

from __future__ import annotations

from cloud_gws.flatten import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_gws.collect import collect
    from cloud_gws.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_gws - Google Workspace audit activity viewer", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a Workspace audit export file / folder",
              open_is_dir=True, multi=True, alert_keys=("notable",))
