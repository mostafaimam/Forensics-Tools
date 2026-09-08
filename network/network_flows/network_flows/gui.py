"""Graphical viewer for network_flows (see ``network_flows --gui``)."""

from __future__ import annotations

from network_flows.analyze import analyze
from network_flows.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    from network_flows.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(c) for c in res.conversations]

    return run("network_flows - conversations", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open NetFlow / IPFIX / sFlow", multi=True,
               alert_keys=("notable",))
