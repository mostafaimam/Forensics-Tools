"""Graphical Prefetch viewer (see ``windows_prefetch --gui``)."""
from __future__ import annotations

from windows_prefetch.guikit import run
from windows_prefetch.models import SUMMARY_COLUMNS
from windows_prefetch.parser import parse_file


def run_gui(paths: list[str]) -> int:
    def load(ps):
        return [parse_file(p).summary_row() for p in ps]

    return run("windows_prefetch — .pf", load, columns=SUMMARY_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open .pf file(s)")
