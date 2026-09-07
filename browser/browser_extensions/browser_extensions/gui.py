"""Graphical viewer for browser_extensions (see ``browser_extensions --gui``)."""

from __future__ import annotations

from browser_extensions.guikit import run
from browser_extensions.output import COLUMNS, row
from browser_extensions.scan import scan


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = scan(list(ps))
        return [row(e) for e in res.extensions]

    return run("browser_extensions - installed extensions", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open profile dir / Preferences", open_is_dir=True,
               alert_keys=("notable",))
