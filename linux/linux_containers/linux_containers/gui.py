"""Graphical viewer for linux_containers (see ``linux_containers --gui``)."""

from __future__ import annotations

from linux_containers.analyze import analyze
from linux_containers.output import row

_COLS = ["engine", "name", "image", "state", "exit_code", "created",
         "entrypoint", "command", "mounts", "ports", "privileged", "cap_add",
         "network_mode", "user", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_containers.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(c) for c in analyze([str(p)]).containers]
        return rows

    return run("linux_containers - container state", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
