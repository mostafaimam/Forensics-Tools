"""Graphical viewer for memory_registry."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from memory_registry.hivescan import scan
    from memory_registry.loader import MemoryImage
    from memory_registry.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for h in scan(img):
                rows.append(h.row())
            img.close()
        return rows

    return run("memory_registry - loaded hives", load,
               columns=["file_name", "dirty", "last_written", "version",
                        "length", "phys_offset"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("dirty",))
