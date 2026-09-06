"""Graphical login-record viewer (see ``linux_utmp --gui``)."""
from __future__ import annotations
from linux_utmp.guikit import run
from linux_utmp.output import RECORD_COLUMNS, record_row
from linux_utmp.utmp import parse as parse_utmp


def run_gui(paths):
    def load(ps):
        rows = []
        for p in ps:
            with open(p, "rb") as fh:
                data = fh.read()
            if data[:2] == b"\x1f\x8b":
                import gzip
                data = gzip.decompress(data)
            for r in parse_utmp(data, False):
                rows.append(record_row(r, p))
        return rows
    return run("linux_utmp — login records", load, columns=RECORD_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open wtmp / btmp / utmp")
