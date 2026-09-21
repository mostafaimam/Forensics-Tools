"""Graphical viewer for browser_localstorage."""

from __future__ import annotations

from browser_localstorage.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from browser_localstorage.collect import collect
    from browser_localstorage.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("browser_localstorage - LevelDB key/value recovery", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a LevelDB directory",
               open_is_dir=True, multi=True, alert_keys=("deleted",))
