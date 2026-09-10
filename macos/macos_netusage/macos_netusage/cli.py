from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_netusage import __version__, tracelib
from macos_netusage import flags as _flags
from macos_netusage.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["process", "bundle", "first_seen", "last_seen", "total_in",
           "total_out", "wifi_in", "wifi_out", "wwan_in", "wwan_out",
           "wired_in", "wired_out", "rows", "severity", "source", "notable"]


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    return [q for q in p.rglob("netusage.sqlite") if q.is_file()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_netusage",
        description="Parse netusage.sqlite: per-process network usage from "
                    "/private/var/networkd. Joins ZLIVEUSAGE to ZPROCESS for "
                    "one row per process - cumulative bytes in / out split "
                    "by interface class (Wi-Fi / WWAN / wired), with "
                    "first-seen / last-seen timestamps (Mac absolute time -> "
                    "UTC). ZNETWORKATTACHMENT gives the interface / SSID "
                    "windows (--attachments). The macOS equivalent of "
                    "Windows SRUM's network table. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_netusage netusage.sqlite --csv net.csv\n"
                "  macos_netusage /Volumes/Macintosh\\ HD --min-out 50000000\n"
                "  macos_netusage netusage.sqlite --grep 'curl|python'\n"
                "  macos_netusage netusage.sqlite --notable-only "
                "--min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a netusage.sqlite or a mounted macOS volume")
    p.add_argument("--version", action="version",
                   version=f"macos_netusage {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--attachments", action="store_true",
                   help="show the ZNETWORKATTACHMENT interface / SSID list "
                        "instead of the process usage")
    p.add_argument("--grep", metavar="REGEX",
                   help="match the process name / bundle")
    p.add_argument("--min-out", type=int, default=0,
                   help="only processes with at least this many bytes sent")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _hb(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024
    return f"{n}B"


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from macos_netusage.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_netusage", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no netusage.sqlite found", file=sys.stderr)
        return 2

    procs = []
    atts = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            res = parse(str(db))
        except Exception as e:                    # noqa: BLE001
            ctx.error("netusage-error", f"{db}: {e}")
            continue
        procs += res.processes
        atts += res.attachments
        for e in res.errors:
            ctx.partial("schema", e)

    if a.attachments:
        rows = [x.row() for x in atts]
        cols = ["identifier", "kind", "first_seen", "last_seen"]
        if a.csv:
            tracelib.write_csv(rows, a.csv, cols, ctx,
                               confidence="high", tz="utc-native")
        if a.json:
            tracelib.write_json(rows, a.json, ctx,
                                confidence="high", tz="utc-native")
        if not a.quiet and not (a.csv or a.json):
            for r in rows:
                print(f"{r['kind']:<10} {r['identifier']:<28} "
                      f"{r['first_seen']} .. {r['last_seen']}")
        ctx.finish(outputs=[a.csv, a.json])
        print(f"macos_netusage: {len(rows)} attachment(s)", file=sys.stderr)
        return 0 if rows else 1

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for pu in procs:
        r = pu.row()
        r["severity"] = _flags.severity(pu.notable)
        if a.min_out and r["total_out"] < a.min_out:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['process']} {r['bundle']}"):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['process']:<32} out {_hb(r['total_out']):>10}  "
                  f"in {_hb(r['total_in']):>10}  "
                  f"{r['first_seen'][:10]}..{r['last_seen'][:10]}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_netusage: {len(procs)} process(es) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
