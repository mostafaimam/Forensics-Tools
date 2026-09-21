"""Graphical viewer for browser_favicons."""

from __future__ import annotations

from browser_favicons.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from browser_favicons.collect import collect
    from browser_favicons.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("browser_favicons - icon-to-page-URL map", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Favicons / favicons.sqlite / profile folder",
               open_is_dir=True, multi=True,
               alert_keys=("cleared_from_history",))
