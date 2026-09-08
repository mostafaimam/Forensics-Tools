"""Graphical viewer for browser_autofill (see ``browser_autofill --gui``)."""

from __future__ import annotations

from browser_autofill.analyze import analyze
from browser_autofill.output import COLUMNS, row

_COLS = ["last_used", "first_used", "browser", "kind", "name", "value",
         "detail", "count", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_autofill.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(r) for r in res.records]

    return run("browser_autofill - form history & profiles", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Web Data / formhistory / folder", multi=True,
               alert_keys=("notable",))
