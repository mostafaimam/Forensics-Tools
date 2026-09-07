"""Graphical viewer for memory_cmdline (see ``memory_cmdline --gui``)."""

from __future__ import annotations

from memory_cmdline.cmdline import scan
from memory_cmdline.guikit import run
from memory_cmdline.loader import MemoryImage
from memory_cmdline.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for r in scan(img):
                rows.append(row(r))
            img.close()
        return rows

    return run("memory_cmdline - process command lines", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("notable",))
