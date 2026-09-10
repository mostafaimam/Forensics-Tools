"""Graphical viewer for windows_defender."""

from __future__ import annotations

_COLS = ["time", "kind", "threat", "path", "user", "process", "action",
         "event_id", "detail", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_defender.collect import collect
    from windows_defender.guikit import run

    def load(ps):
        res = collect([str(p) for p in ps])
        return res.rows

    return run("windows_defender - Defender detection timeline", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Defender folder / MPLog / EVTX / hive",
               open_is_dir=True, multi=True, alert_keys=("notable",))
