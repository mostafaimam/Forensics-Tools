"""Graphical jump-list viewer (see ``windows_jumplist --gui``)."""
from __future__ import annotations

from windows_jumplist.cli import COLUMNS, _rows
from windows_jumplist.guikit import run
from windows_jumplist.jumplist import parse_file


def run_gui(paths: list[str]) -> int:
    def load(ps):
        rows = []
        for p in ps:
            rows += _rows(parse_file(p))
        return rows

    return run("windows_jumplist — automaticDestinations", load,
               columns=COLUMNS, initial=[p for p in paths if p] or None,
               open_label="Open *.automaticDestinations-ms")
