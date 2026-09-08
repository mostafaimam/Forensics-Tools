"""Graphical viewer for network_logs (see ``network_logs --gui``)."""

from __future__ import annotations

from network_logs.analyze import analyze
from network_logs.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    from network_logs.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(e) for e in res.events]

    return run("network_logs - normalised events", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open firewall / proxy / IDS logs", multi=True,
               alert_keys=("notable",))
