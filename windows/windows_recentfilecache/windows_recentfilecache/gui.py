"""Graphical viewer for windows_recentfilecache."""

from __future__ import annotations

_COLS = ["index", "name", "path", "file_mtime", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_recentfilecache.collect import collect
    from windows_recentfilecache.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_recentfilecache - RecentFileCache.bcf", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RecentFileCache.bcf / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
