from __future__ import annotations

import sys
import argparse
from pathlib import Path

from cloud_gws import __version__, tracelib
from cloud_gws.collect import collect
from cloud_gws.flatten import COLUMNS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud_gws",
        description="Normalise Google Workspace audit activity (Admin "
                    "SDK Reports API JSON export, covering login/admin/"
                    "drive/token/groups/mobile/calendar categories) into "
                    "one row per event. Flags login failures, suspicious "
                    "logins, admin role changes, third-party OAuth "
                    "grants, external Drive sharing, and 2SV disablement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  cloud_gws activities.json\n"
                "  cloud_gws ./gws-export --application drive "
                "--notable-only --csv events.csv\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="an export file, or a directory to search "
                   "recursively")
    p.add_argument("--version", action="version",
                   version=f"cloud_gws {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--application", help="substring filter on "
                   "applicationName (login, admin, drive, token, ...)")
    p.add_argument("--actor", help="substring filter on actor email")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from cloud_gws.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "cloud_gws", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect([a.target])
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.application:
        rows = [r for r in rows
               if a.application.lower() in r["application"].lower()]
    if a.actor:
        rows = [r for r in rows
               if a.actor.lower() in r["actor_email"].lower()]
    if a.notable_only:
        rows = [r for r in rows if r["notable"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = f"  [{r['notable']}]" if r["notable"] else ""
            print(f"{r['time']}  {r['application']:<10} "
                 f"{r['event_name']:<24} {r['actor_email']}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"cloud_gws: {len(rows)} event(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
