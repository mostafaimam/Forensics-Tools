"""Graphical Recycle Bin viewer (see ``windows_recycle --gui``)."""
from __future__ import annotations

from windows_recycle.guikit import run
from windows_recycle.models import ROW_COLUMNS
from windows_recycle.scanner import scan


def run_gui(paths: list[str]) -> int:
    def load(ps):
        return [r.as_row() for r in scan(list(ps)).records]

    return run("windows_recycle — Recycle Bin", load, columns=ROW_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open $Recycle.Bin folder", open_is_dir=True)
