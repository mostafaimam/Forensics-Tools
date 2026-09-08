from __future__ import annotations

import argparse
import sys
from pathlib import Path

from network_arp import __version__
from network_arp.analyze import analyze
from network_arp.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_arp",
        description="Build an IP <-> MAC <-> hostname <-> time map from ISC "
                    "dhcpd.leases, the Windows DHCP audit CSV, 'arp -a' / "
                    "'ip neigh' dumps and ARP frames in a pcap. Flags address "
                    "conflicts, gratuitous ARP, one MAC on many IPs and "
                    "locally-administered (randomised) MACs. Pure standard "
                    "library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  network_arp /var/lib/dhcp/dhcpd.leases\n"
                "  network_arp arp.txt dhcpd.leases capture.pcap --csv map.csv\n"
                "  network_arp *.pcap --notable-only\n"
                "  network_arp leases.txt --ip 192.168.1.50\n"
                "  network_arp leases.txt --mac aa:bb:cc:dd:ee:ff\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_arp {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--ip", help="only bindings for this IP")
    p.add_argument("--mac", help="only bindings for this MAC")
    p.add_argument("--host", metavar="NAME",
                   help="only bindings with this hostname (substring)")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--conflicts-only", action="store_true",
                   help="only IPs claimed by more than one MAC")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_arp.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one input file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    from network_arp import oui
    want_mac = oui.norm(a.mac) if a.mac else None
    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} observations")
            sys.stderr.flush()

    res = analyze([str(p) for p in a.paths], progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for b in res.bindings:
        r = row(b)
        if a.ip and r["ip"] != a.ip:
            continue
        if want_mac and r["mac"] != want_mac:
            continue
        if a.host and a.host.lower() not in r["hostnames"].lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.conflicts_only and "claimed by" not in r["notable"]:
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.conflicts), end="")

    src = ", ".join(f"{k}:{v}" for k, v in sorted(res.sources.items()))
    print(f"network_arp: {res.observations} observations ({src or 'none'}) -> "
          f"{len(rows)} binding(s), {len(res.conflicts)} conflict(s)",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
