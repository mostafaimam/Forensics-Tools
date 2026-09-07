"""Graphical viewer for browser_history (see ``browser_history --gui``)."""

from __future__ import annotations

from browser_history.guikit import run
from browser_history.output import COLUMNS, row
from browser_history.scan import scan


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = scan(list(ps))
        return [row(e) for e in res.entries]

    return run("browser_history - web history & downloads", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open profile dir / DB", open_is_dir=True,
               alert_keys=("notable",))
