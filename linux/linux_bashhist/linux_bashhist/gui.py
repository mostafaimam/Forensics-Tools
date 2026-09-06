"""Graphical shell-history viewer (see ``linux_bashhist --gui``)."""
from __future__ import annotations
from pathlib import Path
from linux_bashhist.collect import collect_root
from linux_bashhist.guikit import run
from linux_bashhist.output import COLUMNS, entry_row


def run_gui(root):
    def load(ps):
        rows = []
        for p in ps:
            rows += [entry_row(e) for e in collect_root(Path(p)) if e.command]
        return rows
    return run("linux_bashhist — shell history", load, columns=COLUMNS,
               initial=[p for p in root if p] or None,
               open_label="Scan root (/ or a mount)", open_is_dir=True,
               alert_keys=("notable",))
