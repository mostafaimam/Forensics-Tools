from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_srum import __version__, tracelib
from windows_srum.analyze import analyze
from windows_srum.output import columns, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_srum",
        description="Parse SRUDB.dat (System Resource Usage Monitor) into one "
                    "normalised timeline row per app per hourly bucket: "
                    "network bytes sent / received per interface, connected "
                    "seconds, per-app CPU cycle time and disk bytes, energy "
                    "usage and push-notification activity. Resolves the "
                    "numeric AppId / UserId via SruDbIdMapTable to the "
                    "application path and the user SID. Flags apps run from a "
                    "writable path, large outbound transfers and LOLBins with "
                    "network usage. Vendors the ESE reader; read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_srum SRUDB.dat --csv srum.csv\n"
                "  windows_srum SRUDB.dat --provider network-data "
                "--min-bytes-sent 10000000\n"
                "  windows_srum SRUDB.dat --app powershell --json ps.json\n"
                "  windows_srum SRUDB.dat --notable-only --min-severity high\n"))
    p.add_argument("paths", nargs="+", type=Path, help="SRUDB.dat file(s)")
    p.add_argument("--version", action="version",
                   version=f"windows_srum {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--provider", action="append",
                   help="only this provider (network-data / "
                        "application-resource / ...) - repeatable")
    p.add_argument("--app", help="substring / regex match on the app path")
    p.add_argument("--user", help="substring match on the resolved user SID")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--min-bytes-sent", type=int, default=0)
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
        from windows_srum.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_srum", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in strpaths:
        ctx.add_input(p)

    res = analyze(strpaths)
    for e in res.errors:
        ctx.error("srum-error", e)
    if res.id_map_size == 0:
        ctx.partial("no-id-map", "SruDbIdMapTable was empty or missing; "
                    "AppId / UserId are shown as numbers")

    provs = set(a.provider) if a.provider else None
    app_rx = re.compile(a.app, re.I) if a.app else None
    cols = columns(res)
    rows = []
    for r in res.rows:
        d = row(r)
        if provs and d["provider"] not in provs:
            continue
        if app_rx and not app_rx.search(d["app"]):
            continue
        if a.user and a.user.lower() not in d["user"].lower():
            continue
        if a.since and (not d["timestamp"] or d["timestamp"][:10] < a.since):
            continue
        if a.until and (not d["timestamp"] or d["timestamp"][:10] > a.until):
            continue
        if a.min_bytes_sent and int(d.get("bytes_sent") or 0) < \
                a.min_bytes_sent:
            continue
        if a.notable_only and not d["notable"]:
            continue
        if a.min_severity and _SEV[d["severity"]] < _SEV[a.min_severity]:
            continue
        rows.append(d)

    if a.csv:
        tracelib.write_csv(rows, a.csv, cols, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_srum: {len(res.rows)} row(s) "
          f"[{', '.join(f'{k}:{v}' for k, v in sorted(res.providers_seen.items()))}]"
          f" -> {len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
