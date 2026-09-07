"""Graphical viewer for memory_malfind (see ``memory_malfind --gui``)."""

from __future__ import annotations

from memory_malfind.guikit import run
from memory_malfind.loader import MemoryImage
from memory_malfind.malfind import scan
from memory_malfind.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for d in scan(img):
                r = row(d)
                r["hexdump"] = d.hexdump
                rows.append(r)
            img.close()
        return rows

    return run("memory_malfind - injected / unbacked executable memory", load,
               columns=COLUMNS + ["hexdump"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("verdict",))
