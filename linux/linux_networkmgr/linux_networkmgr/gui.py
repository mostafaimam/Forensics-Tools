"""Graphical viewer for linux_networkmgr (see ``linux_networkmgr --gui``)."""

from __future__ import annotations

from linux_networkmgr.collect import collect
from linux_networkmgr.output import row

_COLS = ["kind", "name", "conn_type", "autoconnect", "last_used", "ssid",
         "security", "secret_stored", "cloned_mac", "ipv4_method", "addresses",
         "gateway", "dns", "proxy", "vpn_gateway", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from linux_networkmgr.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows += [row(it) for it in collect(str(p)).items]
        return rows

    return run("linux_networkmgr - saved networks", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a filesystem root", multi=True,
               open_is_dir=True, alert_keys=("notable",))
