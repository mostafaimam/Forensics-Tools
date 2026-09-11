"""Graphical viewer for macos_coreanalytics."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from macos_coreanalytics.collect import collect
    from macos_coreanalytics.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("macos_coreanalytics - app usage aggregates", load,
               columns=["timestamp", "event_name", "app", "launches",
                        "foreground_seconds", "active_seconds", "extra"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open .core_analytics / folder",
               open_is_dir=True, multi=True)
