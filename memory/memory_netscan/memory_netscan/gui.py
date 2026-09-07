"""Graphical viewer for memory_netscan (see ``memory_netscan --gui``)."""

from __future__ import annotations

from memory_netscan.guikit import run
from memory_netscan.loader import MemoryImage
from memory_netscan.netscan import scan
from memory_netscan.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for e in scan(img):
                rows.append(row(e))
            img.close()
        return rows

    return run("memory_netscan - connections & sockets", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("remote_addr",))
