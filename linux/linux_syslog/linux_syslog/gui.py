"""Graphical syslog viewer (see ``linux_syslog --gui``)."""
from __future__ import annotations
from datetime import timezone
from linux_syslog.collect import iter_records
from linux_syslog.guikit import run
from linux_syslog.output import RECORD_COLUMNS, record_row


def run_gui(paths):
    def load(ps):
        rows = []
        for p in ps:
            from pathlib import Path
            for rec in iter_records(Path(p), timezone.utc):
                rows.append(record_row(rec))
        return rows
    return run("linux_syslog — records", load, columns=RECORD_COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open syslog / auth.log")
