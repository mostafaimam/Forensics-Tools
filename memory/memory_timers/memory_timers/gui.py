"""Graphical viewer for memory_timers."""

from __future__ import annotations

from memory_timers.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from memory_timers.collect import scan_image
    from memory_timers.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(scan_image(str(p)).rows)
        return rows

    return run("memory_timers - KTIMER structural scan", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a memory image",
              open_is_dir=False, multi=True)
