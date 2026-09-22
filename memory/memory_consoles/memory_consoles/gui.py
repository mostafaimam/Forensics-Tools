"""Graphical viewer for memory_consoles."""

from __future__ import annotations

from memory_consoles.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from memory_consoles.collect import scan_image
    from memory_consoles.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(scan_image(str(p)).rows)
        return rows

    return run("memory_consoles - console process / command-text scan",
              load, columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a memory image",
              open_is_dir=False, multi=True)
