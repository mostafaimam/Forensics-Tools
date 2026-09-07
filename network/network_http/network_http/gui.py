"""Graphical viewer for network_http (see ``network_http --gui``)."""

from __future__ import annotations

from network_http.carve import analyze
from network_http.flags import severity
from network_http.guikit import run

_COLS = ["time", "direction", "client", "server", "port", "method", "url",
         "status", "filename", "size", "type", "encoding", "sha256",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = analyze(list(ps), keep_bodies=False)
        rows = []
        for o in res.objects:
            t = o.content_type or ""
            if o.detected_type and o.detected_type != o.content_type:
                t = f"{t or '?'} / {o.detected_type}"
            rows.append({
                "time": o.ts, "direction": o.direction, "client": o.client,
                "server": o.server, "port": o.server_port, "method": o.method,
                "url": o.url, "status": o.status or "",
                "filename": o.filename, "size": o.size, "type": t,
                "encoding": o.encoding, "sha256": o.sha256,
                "severity": severity(o.notable),
                "notable": "; ".join(o.notable)})
        rows.sort(key=lambda r: r["time"] or "~")
        return rows

    return run("network_http - carved HTTP objects", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open .pcap / .pcapng", multi=True,
               alert_keys=("notable",))
