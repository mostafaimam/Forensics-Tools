"""Graphical viewer for browser_shortcuts."""

from __future__ import annotations

from browser_shortcuts.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from browser_shortcuts.collect import collect
    from browser_shortcuts.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("browser_shortcuts - omnibox intent artifacts", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Shortcuts / Top Sites / profile folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
