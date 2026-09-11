"""Graphical viewer for macos_screentime."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from macos_screentime.collect import collect
    from macos_screentime.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("macos_screentime - Screen Time usage totals", load,
               columns=["date", "entity", "app", "duration_s", "start",
                        "end", "device"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RMAdminStore-Local.sqlite / folder",
               open_is_dir=True, multi=True)
