"""Graphical viewer for windows_spooler."""

from __future__ import annotations

_COLS = ["submit_time", "job_id", "user", "machine", "document", "printer",
         "driver", "datatype", "spl_format", "spl_pages", "spl_bytes",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_spooler.collect import collect
    from windows_spooler.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("windows_spooler - print spool jobs", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open PRINTERS folder / .shd / .spl",
               open_is_dir=True, multi=True, alert_keys=("notable",))
