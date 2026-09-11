"""Graphical viewer for memory_handles."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from memory_handles import flags
    from memory_handles.handles import enumerate_file_handles
    from memory_handles.loader import MemoryImage
    from memory_handles.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            img = MemoryImage(p)
            for h in enumerate_file_handles(img):
                notable = flags.flag(h.process, h.name)
                row = h.row()
                row["notable"] = ";".join(notable)
                row["severity"] = flags.severity(notable)
                rows.append(row)
            img.close()
        return rows

    return run("memory_handles - open file handles", load,
               columns=["pid", "process", "handle", "name", "severity",
                        "notable"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open RAM dump", multi=False,
               alert_keys=("notable",))
