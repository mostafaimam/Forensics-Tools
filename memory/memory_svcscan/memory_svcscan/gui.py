"""Graphical viewer for memory_svcscan (see ``memory_svcscan --gui``)."""

from __future__ import annotations

from memory_svcscan.analyze import scan
from memory_svcscan.guikit import run
from memory_svcscan.loader import MemoryImage
from memory_svcscan.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for r in scan(img):
                rows.append(row(r))
            img.close()
        return rows

    return run("memory_svcscan - Windows services", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("notable",))
