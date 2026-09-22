"""Graphical viewer for memory_dumpfiles."""

from __future__ import annotations

from memory_dumpfiles.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from memory_dumpfiles.collect import scan_image
    from memory_dumpfiles.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(scan_image(str(p)).rows)
        return rows

    return run("memory_dumpfiles - cached-file-content reconstruction",
              load, columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a memory image",
              open_is_dir=False, multi=True)
