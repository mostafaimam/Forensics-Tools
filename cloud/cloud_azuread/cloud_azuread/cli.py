from __future__ import annotations

import sys
import argparse
from pathlib import Path

from cloud_azuread import __version__, tracelib
from cloud_azuread.collect import collect
from cloud_azuread.flatten import COLUMNS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud_azuread",
        description="Normalise Entra ID (Azure AD) sign-in and directory "
                    "audit log JSON exports (portal export, Microsoft "
                    "Graph API, or Log Analytics) into one row per event. "
                    "Flags legacy authentication, risky sign-ins, "
                    "conditional-access failures, a user's first sign-in "
                    "from a new country, and sensitive audit activities "
                    "(role/consent/credential changes).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  cloud_azuread signins.json\n"
                "  cloud_azuread ./entra-export --kind signin "
                "--notable-only --csv events.csv\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a log export file, or a directory to search "
                   "recursively")
    p.add_argument("--version", action="version",
                   version=f"cloud_azuread {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["signin", "audit"])
    p.add_argument("--user", help="substring filter on actor")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from cloud_azuread.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "cloud_azuread", __version__)
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
    if a.kind:
        rows = [r for r in rows if r["kind"] == a.kind]
    if a.user:
        rows = [r for r in rows if a.user.lower() in r["actor"].lower()]
    if a.notable_only:
        rows = [r for r in rows if r["notable"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = f"  [{r['notable']}]" if r["notable"] else ""
            print(f"{r['time']}  {r['kind']:<7} {r['actor']:<28} "
                 f"{r['activity']}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"cloud_azuread: {len(rows)} event(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
