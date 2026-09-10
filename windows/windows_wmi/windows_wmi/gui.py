"""Graphical viewer for windows_wmi."""

from __future__ import annotations

_COLS = ["type", "class", "name", "namespace", "action_kind", "query",
         "action", "filter", "consumer", "live", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_wmi.collect import collect
    from windows_wmi.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_wmi - WMI subscription persistence", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Repository / OBJECTS.DATA / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
