"""Graphical viewer for cloud_azuread."""

from __future__ import annotations

from cloud_azuread.flatten import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_azuread.collect import collect
    from cloud_azuread.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_azuread - Entra ID sign-in & audit log viewer", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a log export file / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
