"""Graphical viewer for network_pcap (see ``network_pcap --gui``)."""

from __future__ import annotations

from network_pcap.analyze import analyze
from network_pcap.flags import severity
from network_pcap.guikit import run
from network_pcap.output import _iso

_COLS = ["time", "view", "proto", "service", "client", "server", "port",
         "packets", "bytes", "info", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        cap = analyze(list(ps))
        rows = []
        for f in cap.flows:
            port = (f.b_port if f.server_ip == f.b_ip else f.a_port) or ""
            rows.append({
                "time": _iso(f.first_ts), "view": "flow", "proto": f.proto,
                "service": f.service, "client": f.client_ip,
                "server": f.server_ip, "port": port, "packets": f.packets,
                "bytes": f.bytes, "info": f"{f.duration}s  {''.join(sorted(f.tcp_flags))}",
                "severity": severity(f.notable),
                "notable": ";".join(f.notable)})
        for d in cap.dns:
            if d.response:
                continue
            ans = next((x for x in cap.dns if x.query == d.query
                        and x.response), None)
            info = d.query + (f"  ->  " + ", ".join(
                f"{t}={v}" for t, v in ans.answers if v) if ans
                and ans.answers else "")
            rows.append({
                "time": _iso(d.ts), "view": "dns", "proto": "UDP",
                "service": "dns", "client": d.client, "server": d.server,
                "port": 53, "packets": "", "bytes": "",
                "info": f"{d.qtype}  {info}",
                "severity": severity(d.notable),
                "notable": ";".join(d.notable)})
        for h in cap.http:
            rows.append({
                "time": _iso(h.ts), "view": "http", "proto": "TCP",
                "service": "http", "client": h.client, "server": h.server,
                "port": h.server_port, "packets": "", "bytes": "",
                "info": f"{h.method} {h.url}"
                + (f"  ({h.status})" if h.status else ""),
                "severity": severity(h.notable),
                "notable": ";".join(h.notable)})
        rows.sort(key=lambda r: r["time"] or "~")
        return rows

    return run("network_pcap - flows / DNS / HTTP", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open .pcap / .pcapng", multi=True,
               alert_keys=("notable",))
