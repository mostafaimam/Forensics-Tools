"""Graphical viewer for cloud_m365ual."""

from __future__ import annotations

from cloud_m365ual.flatten import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_m365ual.collect import collect
    from cloud_m365ual.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_m365ual - Unified Audit Log viewer", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a UAL export file / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
