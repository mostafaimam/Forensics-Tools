"""Graphical viewer for linux_units (see ``linux_units --gui``)."""

from __future__ import annotations

from linux_units.collect import collect
from linux_units.output import row

_COLS = ["name", "type", "description", "exec_start", "user", "enabled", "restart", "drop_ins", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_units.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(u) for u in collect(str(p)).units]
        return rows

    return run("linux_units - systemd units", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
