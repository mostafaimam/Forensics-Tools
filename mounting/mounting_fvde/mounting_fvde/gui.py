"""Graphical viewer for mounting_fvde's `info` (candidate discovery)."""

from __future__ import annotations

from mounting_fvde.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from mounting_fvde.collect import collect
    from mounting_fvde.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(collect(str(p)).rows)
        return rows

    return run("mounting_fvde - CoreStorage key-blob candidate finder",
              load, columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a plist or image file",
              open_is_dir=False, multi=True)
