"""Graphical viewer for memory_filescan."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from memory_filescan import flags
    from memory_filescan.filescan import scan
    from memory_filescan.loader import MemoryImage
    from memory_filescan.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for h in scan(img):
                notable = flags.flag(h.name)
                row = h.row()
                row["notable"] = ";".join(notable)
                row["severity"] = flags.severity(notable)
                rows.append(row)
            img.close()
        return rows

    return run("memory_filescan - open file objects", load,
               columns=["name", "device", "severity", "notable"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("notable",))
