"""Graphical memory-strings viewer (see ``memory_strings gui``)."""
from __future__ import annotations
from memory_strings.guikit import run
from memory_strings.loader import MemoryImage
from memory_strings.output import COLUMNS, row
from memory_strings.scan import scan


def run_gui(paths):
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for h in scan(img, min_len=6, classified_only=True, limit=20000):
                rows.append(row(h))
            img.close()
        return rows
    return run("memory_strings — classified strings", load, columns=COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("category",))
