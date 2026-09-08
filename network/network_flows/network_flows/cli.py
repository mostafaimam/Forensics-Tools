from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from network_flows import __version__
from network_flows.analyze import analyze
from network_flows.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_flows",
        description="Read exported flow records - NetFlow v5 / v9, IPFIX "
                    "(with template handling) and sFlow flow samples - "
                    "reassemble them into conversations, and summarise "
                    "top talkers, server ports and protocols. Flags large "
                    "transfers, outbound-heavy flows, regular beacons and "
                    "scan fan-out. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  network_flows export.netflow\n"
                "  network_flows *.ipfix --csv conversations.csv\n"
                "  network_flows flows.bin --notable-only --min-severity high\n"
                "  network_flows flows.bin --host 10.0.0.50 --summary\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_flows {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--host", metavar="IP/CIDR",
                   help="only conversations touching this address / range")
    p.add_argument("--port", type=int, help="only this server port")
    p.add_argument("--proto", help="only this protocol (TCP / UDP / ICMP / ...)")
    p.add_argument("--summary", action="store_true",
                   help="append top-talker / port / protocol summaries")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _match_host(spec, cip, sip) -> bool:
    try:
        net = ipaddress.ip_network(spec, strict=False)
        return any(ipaddress.ip_address(x) in net for x in (cip, sip) if x)
    except ValueError:
        return spec in (cip, sip)


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_flows.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a flow export file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} flows")
            sys.stderr.flush()

    res = analyze([str(p) for p in a.paths], progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for c in res.conversations:
        r = row(c)
        if a.host and not _match_host(a.host, r["client"], r["server"]):
            continue
        if a.port and r["server_port"] != a.port:
            continue
        if a.proto and r["proto"].upper() != a.proto.upper():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res if a.summary else None), end="")

    kinds = ", ".join(f"{k}:{v}" for k, v in sorted(res.kinds.items()))
    fl = sum(1 for r in rows if r["notable"])
    print(f"network_flows: {res.flows} flow records ({kinds or 'none'}) -> "
          f"{len(rows)} conversation(s), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
