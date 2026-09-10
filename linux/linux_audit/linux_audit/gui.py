"""Graphical viewer for linux_audit (see ``linux_audit --gui``)."""

from __future__ import annotations

from linux_audit.analyze import analyze
from linux_audit.output import row

_COLS = ["ts", "action", "success", "syscall", "exe", "command", "key",
         "uid", "auid", "actor", "addr", "summary", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_audit.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(ev) for ev in analyze([str(p)]).events]
        return rows

    return run("linux_audit - auditd events", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
