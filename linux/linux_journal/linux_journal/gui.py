"""Graphical viewer for linux_journal (see ``linux_journal --gui``)."""

from __future__ import annotations

from linux_journal.collect import collect
from linux_journal.output import row

_COLS = ["ts", "priority", "unit", "comm", "pid", "uid", "transport",
         "message", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_journal.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(e) for e in collect([str(p)]).entries]
        return rows

    return run("linux_journal - systemd journal", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
