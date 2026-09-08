"""Graphical viewer for network_dns (see ``network_dns --gui``)."""

from __future__ import annotations

from network_dns.analyze import analyze
from network_dns.output import COLUMNS, row


def run_gui(paths: list[str] | None = None) -> int:
    from network_dns.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(r) for r in res.names]

    return run("network_dns - resolved names", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open pcap / displaydns / hosts", multi=True,
               alert_keys=("notable",))
