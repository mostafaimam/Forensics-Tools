from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_networkmgr import __version__, tracelib
from linux_networkmgr.collect import collect
from linux_networkmgr.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_networkmgr",
        description="Collect saved network configuration and joined networks "
                    "under a mounted image or a live root: NetworkManager "
                    "keyfile profiles (id / uuid / type / autoconnect / "
                    "last-used, Wi-Fi SSID / BSSID / security, IPv4 method + "
                    "addresses + DNS + gateway + routes, proxy, cloned MAC, "
                    "VPN), wpa_supplicant network blocks, systemd-networkd "
                    "units, a best-effort read of netplan YAML, /etc/hosts "
                    "and /etc/resolv.conf. Secret values are never printed - "
                    "only that a secret is stored. Flags plaintext Wi-Fi / "
                    "802.1x / VPN secrets, autoconnect to open Wi-Fi, spoofed "
                    "MACs, proxies, /etc/hosts overrides of public domains and "
                    "unexpected DNS servers. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_networkmgr /mnt/evidence\n"
                "  linux_networkmgr / --csv networks.csv\n"
                "  linux_networkmgr /mnt/img --kind nm-connection\n"
                "  linux_networkmgr /mnt/img --notable-only --min-severity "
                "medium\n"))
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to inspect (mounted image or /)")
    p.add_argument("--version", action="version",
                   version=f"linux_networkmgr {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["nm-connection", "wpa-network",
                                      "networkd", "netplan", "hosts-entry",
                                      "resolv"],
                   help="only this kind of item")
    p.add_argument("--type", dest="conn_type",
                   help="only this connection type (wifi / ethernet / vpn)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / ssid / addresses / dns / detail")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from linux_networkmgr.gui import run_gui
        return run_gui([str(a.root)] if a.root else [])
    if not a.root:
        build_parser().error("a filesystem root is required (or use --gui)")
    if not a.root.exists():
        print(f"not found: {a.root}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "linux_networkmgr", __version__)
    try:
        ctx.limits.check_paths([str(a.root)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(str(a.root))
    for f in res.files:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("read-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for it in res.items:
        r = row(it)
        if a.kind and r["kind"] != a.kind:
            continue
        if a.conn_type and r["conn_type"] != a.conn_type:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["name"], r["ssid"], r["addresses"], r["dns"], r["detail"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"linux_networkmgr: {len(res.items)} item(s) from {len(res.files)} "
          f"file(s) -> {len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
