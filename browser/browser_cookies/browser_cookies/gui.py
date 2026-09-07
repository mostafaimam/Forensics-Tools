"""Graphical viewer for browser_cookies (see ``browser_cookies --gui``)."""

from __future__ import annotations

from browser_cookies.guikit import run
from browser_cookies.output import COLUMNS, row
from browser_cookies.scan import scan


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = scan(list(ps))
        return [row(c) for c in res.cookies]

    return run("browser_cookies - browser cookies", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open profile dir / Cookies file", open_is_dir=True,
               alert_keys=("notable",))
