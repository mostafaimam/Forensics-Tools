"""Graphical .evtx viewer (see ``windows_evtx --gui``)."""
from __future__ import annotations

from windows_evtx.evtx import parse_evtx
from windows_evtx.guikit import run
from windows_evtx.output import CSV_COLUMNS, _row


def run_gui(paths: list[str]) -> int:
    def load(ps):
        rows = []
        for p in ps:
            with open(p, "rb") as fh:
                for rec in parse_evtx(fh.read()):
                    rows.append(_row(rec, p))
        return rows

    return run("windows_evtx — event logs", load, columns=CSV_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open .evtx")
