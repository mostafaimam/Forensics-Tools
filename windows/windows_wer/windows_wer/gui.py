"""Graphical viewer for windows_wer."""

from __future__ import annotations

_COLS = ["time", "event_type", "app_name", "app_path", "app_version",
         "mod_name", "mod_path", "exception_code", "pid", "friendly",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_wer.collect import collect
    from windows_wer.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_wer - Windows Error Reporting", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open .wer / WER store / folder",
               open_is_dir=True, multi=True, alert_keys=("notable",))
