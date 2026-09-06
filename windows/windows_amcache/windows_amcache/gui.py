"""Graphical Amcache.hve viewer (see ``windows_amcache --gui``)."""

from __future__ import annotations

from windows_amcache.amcache import parse
from windows_amcache.cli import COLUMNS
from windows_amcache.guikit import run


def run_gui(paths: list[str]) -> int:
    def load(ps):
        rows = []
        for p in ps:
            with open(p, "rb") as fh:
                for r in parse(fh.read()):
                    rows.append(r.as_row())
        return rows

    return run("windows_amcache — Amcache.hve", load, columns=COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open Amcache.hve", multi=False)
