"""Graphical viewer for cloud_cloudtrail."""

from __future__ import annotations

from cloud_cloudtrail.flatten import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from cloud_cloudtrail.collect import collect
    from cloud_cloudtrail.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("cloud_cloudtrail - AWS CloudTrail event viewer", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open CloudTrail file / export folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
