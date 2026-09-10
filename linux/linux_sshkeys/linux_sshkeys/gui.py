"""Graphical viewer for linux_sshkeys (see ``linux_sshkeys --gui``)."""

from __future__ import annotations

from linux_sshkeys.collect import collect
from linux_sshkeys.output import rows

_COLS = ["kind", "user", "key_type", "bits", "sha256", "marker", "hosts",
         "options", "comment", "fmt", "encrypted", "keyword", "value",
         "message", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_sshkeys.guikit import run

    def load(ps):
        out = []
        for p in ps:
            out += rows(collect(str(p)))
        return out

    return run("linux_sshkeys - SSH access review", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
