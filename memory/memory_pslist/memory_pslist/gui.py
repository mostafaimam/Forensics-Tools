"""Graphical process list (see ``memory_pslist --gui``)."""
from __future__ import annotations
from memory_pslist.cli import _COLUMNS, _row
from memory_pslist.guikit import run
from memory_pslist.loader import MemoryImage
from memory_pslist.psscan import scan


def run_gui(paths):
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            rows += [_row(x) for x in scan(img)]
            img.close()
        return rows
    return run("memory_pslist — process scan", load, columns=_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("exited",))
