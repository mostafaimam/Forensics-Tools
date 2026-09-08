from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from network_logs import __version__
from network_logs.analyze import analyze
from network_logs.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_logs",
        description="Normalise firewall / proxy / IDS text logs - iptables / "
                    "nftables kernel lines, pflog (tcpdump text), the Windows "
                    "Firewall pfirewall.log, Squid access.log, Zeek conn.log "
                    "(TSV) and Suricata eve.json - into one flow / event "
                    "schema. Flags blocked bursts, IDS alerts, abused ports, "
                    "credentials in proxied URLs and raw-IP requests. Pure "
                    "standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  network_logs /var/log/ufw.log\n"
                "  network_logs conn.log eve.json pfirewall.log --csv events.csv\n"
                "  network_logs *.log --notable-only --min-severity high\n"
                "  network_logs access.log --action deny --src 10.0.0.66\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_logs {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--action", help="only this action (allow / deny / drop / "
                                    "reject / alert / info)")
    p.add_argument("--src", metavar="IP", help="only this source address")
    p.add_argument("--dst", metavar="IP", help="only this destination address")
    p.add_argument("--port", type=int, help="only this destination port")
    p.add_argument("--fmt", help="only events from this log format")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match signature / message / host")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_logs.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one log file is required")
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
    for ev in res.events:
        r = row(ev)
        if a.action and r["action"] != a.action:
            continue
        if a.src and r["src"] != a.src:
            continue
        if a.dst and r["dst"] != a.dst:
            continue
        if a.port and r["dport"] != a.port:
            continue
        if a.fmt and r["fmt"] != a.fmt:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["sev_flag"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['signature']} {r['message']} {r['host']}"):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.findings), end="")

    fmts = ", ".join(f"{k}:{v}" for k, v in sorted(res.formats.items()))
    fl = sum(1 for r in rows if r["notable"])
    print(f"network_logs: {len(res.events)} events ({fmts or 'none'}) -> "
          f"{len(rows)} shown, {fl} flagged, {len(res.findings)} finding(s)",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
