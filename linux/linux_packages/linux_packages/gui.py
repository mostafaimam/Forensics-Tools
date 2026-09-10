"""Graphical viewer for linux_packages (see ``linux_packages --gui``)."""

from __future__ import annotations

from linux_packages.analyze import analyze
from linux_packages.output import row

_COLS = ["ts", "action", "package", "version", "from_version", "source",
         "requested_by", "command", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_packages.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(ev) for ev in analyze([str(p)]).events]
        return rows

    return run("linux_packages - package history", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
