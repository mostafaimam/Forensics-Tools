"""Graphical viewer for macos_unifiedlog."""

from __future__ import annotations

from macos_unifiedlog.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from macos_unifiedlog.collect import collect
    from macos_unifiedlog.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(collect(str(p)).rows)
        return rows

    return run("macos_unifiedlog - .tracev3 chunk / string viewer", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a .tracev3 file",
              open_is_dir=False, multi=True)
