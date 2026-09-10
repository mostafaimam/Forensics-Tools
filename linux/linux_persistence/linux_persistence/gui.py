"""Graphical viewer for linux_persistence (see ``linux_persistence --gui``)."""

from __future__ import annotations

from linux_persistence.output import row
from linux_persistence.scan import scan

_COLS = ["verdict", "mechanism", "path", "line", "payload", "mtime",
         "world_writable", "why"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_persistence.guikit import run

    def load(ps):
        out = []
        for p in ps:
            out += [row(f) for f in scan(str(p)).findings]
        return out

    return run("linux_persistence - persistence sweep", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("why", "verdict"))
