"""Graphical ShimCache viewer (see ``windows_shimcache --gui``)."""
from __future__ import annotations

from windows_shimcache.cli import COLUMNS, _row
from windows_shimcache.extract import (
    from_blob_file,
    from_hive_file,
    looks_like_hive,
)
from windows_shimcache.guikit import run


def run_gui(paths: list[str]) -> int:
    def load(ps):
        rows = []
        for p in ps:
            data = open(p, "rb").read()
            entries = from_hive_file(p) if looks_like_hive(data) \
                else from_blob_file(p)
            rows += [_row(e, p) for e in entries]
        return rows

    return run("windows_shimcache — AppCompatCache", load, columns=COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open SYSTEM hive / blob")
