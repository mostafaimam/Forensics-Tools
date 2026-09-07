"""Graphical viewer for memory_dlllist (see ``memory_dlllist --gui``)."""

from __future__ import annotations

from memory_dlllist.dlllist import scan
from memory_dlllist.guikit import run
from memory_dlllist.loader import MemoryImage
from memory_dlllist.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for m in scan(img):
                rows.append(row(m))
            img.close()
        return rows

    return run("memory_dlllist - loaded modules", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("notable",))
