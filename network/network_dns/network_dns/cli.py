from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from network_dns import __version__
from network_dns.analyze import analyze
from network_dns.flags import severity
from network_dns.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_dns",
        description="Consolidate DNS evidence - queries / answers from a "
                    "pcap, the Windows 'ipconfig /displaydns' cache, "
                    "systemd-resolved dumps and hosts files - into one "
                    "name-resolution timeline, flagging tunnelling, "
                    "DGA-looking names, payload-carrying record types and "
                    "hosts-file overrides. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  network_dns capture.pcap\n"
                "  network_dns dns.pcapng displaydns.txt /etc/hosts --csv names.csv\n"
                "  network_dns *.pcap --notable-only --min-severity medium\n"
                "  network_dns capture.pcap --grep '\\.top$|dyndns'\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_dns {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX", help="match the name (case-insensitive)")
    p.add_argument("--client", metavar="IP", help="only names queried by this client")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_dns.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one input file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} events")
            sys.stderr.flush()

    res = analyze([str(p) for p in a.paths], progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for rec in res.names:
        if a.client and a.client not in rec.clients:
            continue
        r = row(rec)
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["qname"]):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    src = ", ".join(f"{k}:{v}" for k, v in sorted(res.sources.items()))
    fl = sum(1 for r in rows if r["notable"])
    print(f"network_dns: {res.events} events ({src or 'none'}) -> "
          f"{len(rows)} name(s), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
