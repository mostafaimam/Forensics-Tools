"""Graphical viewer for mounting_partitions (see ``mounting_partitions --gui``)."""

from __future__ import annotations

from mounting_partitions.analyze import analyze

_COLS = ["index", "scheme", "start_lba", "size", "type", "filesystem",
         "label", "bootable", "note"]


def run_gui(paths: list[str] | None = None) -> int:
    from mounting_partitions.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [s.row() for s in analyze(str(p)).slices]
        return rows

    return run("mounting_partitions - disk layout", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a disk image", multi=True,
               alert_keys=("note",))
