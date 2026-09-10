"""Graphical viewer for utilities_strings."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from utilities_strings.guikit import run
    from utilities_strings.strings import scan

    def load(ps):
        rows = []
        for p in ps:
            for hit in scan(str(p), min_len=5, limit=20000):
                rows.append(hit.row(True))
        return rows

    return run("utilities_strings - extracted strings", load,
               columns=["offset", "encoding", "length", "text", "category",
                        "match"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open file / image", multi=True,
               alert_keys=("category",))
