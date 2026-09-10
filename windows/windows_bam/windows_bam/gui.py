"""Graphical viewer for windows_bam (see ``windows_bam --gui``)."""

from __future__ import annotations

from windows_bam import flags as _flags
from windows_bam.bam import parse
from windows_bam.cli import _discover
from pathlib import Path

_COLS = ["last_run", "moderator", "sid", "path", "control_set", "severity",
         "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_bam.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for h in _discover(Path(p)):
                res = parse(h.read_bytes())
                for e in res.entries:
                    e.notable = _flags.flag(e)
                    r = e.row()
                    r["severity"] = _flags.severity(e.notable)
                    rows.append(r)
        return rows

    return run("windows_bam - BAM / DAM last execution", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a SYSTEM hive or root", multi=True,
               alert_keys=("notable",))
