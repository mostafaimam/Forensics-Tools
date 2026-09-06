"""Graphical scheduled-job viewer (see ``linux_cron --gui``)."""
from __future__ import annotations
from pathlib import Path
from linux_cron.collect import collect_root
from linux_cron.guikit import run
from linux_cron.output import COLUMNS, job_row


def run_gui(root):
    def load(ps):
        rows = []
        for p in ps:
            rows += [job_row(j) for j in collect_root(Path(p))]
        return rows
    return run("linux_cron — scheduled jobs", load, columns=COLUMNS,
               initial=[p for p in root if p] or None,
               open_label="Scan root (/ or a mount)", open_is_dir=True,
               alert_keys=("notable",))
