"""Graphical viewer for network_arp (see ``network_arp --gui``)."""

from __future__ import annotations

from network_arp.analyze import analyze
from network_arp.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    from network_arp.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(b) for b in res.bindings]

    return run("network_arp - IP / MAC bindings", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open leases / arp / pcap", multi=True,
               alert_keys=("notable",))
