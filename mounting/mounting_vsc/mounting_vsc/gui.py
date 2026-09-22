"""Graphical viewer for mounting_vsc."""

from __future__ import annotations

from mounting_vsc.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from mounting_vsc.collect import collect
    from mounting_vsc.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(collect(str(p)).rows)
        return rows

    return run("mounting_vsc - VSS identifier / candidate-field scan",
              load, columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a volume/image file",
              open_is_dir=False, multi=True)
