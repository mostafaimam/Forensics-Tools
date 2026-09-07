from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from network_pcap import __version__
from network_pcap.analyze import analyze
from network_pcap.flags import severity
from network_pcap.output import (DNS_COLUMNS, FLOW_COLUMNS, HTTP_COLUMNS,
                                 dns_row, flow_row, http_row, render_dns,
                                 render_flows, render_http, write_csv,
                                 write_json)

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_pcap",
        description="Read a packet capture (pcap / pcapng) and summarise it: "
                    "bidirectional flows, DNS queries, HTTP requests, and "
                    "flags for cleartext credentials, plaintext protocols, "
                    "DNS tunnelling, port scans and high-egress flows. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  network_pcap capture.pcap\n"
            "  network_pcap traffic.pcapng --dns --notable-only\n"
            "  network_pcap *.pcap --http --grep 'login|admin' --csv http.csv\n"
            "  network_pcap c.pcap --flows --host 185.43.99.42 --json f.json\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_pcap {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    view = p.add_mutually_exclusive_group()
    view.add_argument("--flows", action="store_true",
                      help="flow summary (default)")
    view.add_argument("--dns", action="store_true", help="DNS queries/answers")
    view.add_argument("--http", action="store_true", help="HTTP requests")
    p.add_argument("--proto", metavar="P", help="tcp / udp / icmp")
    p.add_argument("--service", metavar="NAME",
                   help="keep flows of this service (http, smb, dns, ...)")
    p.add_argument("--host", metavar="IP", help="either endpoint is this host")
    p.add_argument("--port", type=int, action="append", default=[])
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_pcap.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a pcap / pcapng file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} packets")
            sys.stderr.flush()

    cap = analyze([str(p) for p in a.paths], progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    view = "dns" if a.dns else "http" if a.http else "flows"
    if view == "dns":
        rows = [dns_row(d) for d in cap.dns]
        cols, render = DNS_COLUMNS, render_dns
    elif view == "http":
        rows = [http_row(h) for h in cap.http]
        cols, render = HTTP_COLUMNS, render_http
    else:
        rows = [flow_row(f) for f in cap.flows]
        cols, render = FLOW_COLUMNS, render_flows

    out = []
    for r in rows:
        if a.proto and r.get("proto", "").lower() != a.proto.lower() \
                and view == "flows":
            continue
        if a.service and r.get("service", "").lower() != a.service.lower():
            continue
        if a.host and a.host not in (r.get("client", "") + " "
                                     + r.get("server", "")):
            continue
        if a.port and view == "flows" and r.get("server_port") not in a.port:
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV.get(r.get("severity", "none"), 0) \
                < _SEV[a.min_severity]:
            continue
        if grep:
            hay = " ".join(str(r.get(k, "")) for k in
                           ("url", "query", "client", "server", "user_agent",
                            "notable", "answers", "service"))
            if not grep.search(hay):
                continue
        out.append(r)

    if a.csv:
        write_csv(out, cols, a.csv)
    if a.json:
        write_json(out, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(out), end="")

    fl = sum(1 for r in out if r.get("notable"))
    print(f"network_pcap: {cap.packets} packets ({cap.decoded} decoded) -> "
          f"{len(cap.flows)} flows, {len(cap.dns)} DNS, {len(cap.http)} HTTP; "
          f"showing {len(out)} {view}, {fl} flagged", file=sys.stderr)
    for e in cap.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if out else 1


if __name__ == "__main__":
    raise SystemExit(main())
