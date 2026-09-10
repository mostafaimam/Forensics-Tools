from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_units import __version__, tracelib
from linux_units.collect import collect
from linux_units.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_units",
        description="Inventory systemd unit files under a mounted image or a "
                    "live root: merge drop-ins, resolve the enable state from "
                    "the .wants / .requires symlinks, and list ExecStart, "
                    "Type, User, WantedBy, restart policy and the drop-in "
                    "chain per unit. Flags user-writable ExecStart paths, "
                    "inline shells / download cradles, encoded payloads, "
                    "tight respawn loops and units enabled without an "
                    "[Install] section. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_units /mnt/evidence\n"
                "  linux_units / --csv units.csv\n"
                "  linux_units /mnt/img --notable-only --min-severity high\n"
                "  linux_units /mnt/img --enabled-only --type service\n"))
    p.add_argument("root", nargs="?", type=Path,
                   help="filesystem root to walk (mounted image or /)")
    p.add_argument("--version", action="version",
                   version=f"linux_units {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", help="only this unit type (service / timer / ...)")
    p.add_argument("--scope", choices=["system", "user"])
    p.add_argument("--enabled-only", action="store_true")
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / description / ExecStart")
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
        from linux_units.gui import run_gui
        return run_gui([str(a.root)] if a.root else [])
    if not a.root:
        build_parser().error("a filesystem root is required (or use --gui)")
    if not a.root.exists():
        print(f"not found: {a.root}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "linux_units", __version__)
    try:
        ctx.limits.check_paths([str(a.root)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.root))

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = collect(str(a.root))
    for e in res.errors:
        ctx.error("collect-error", e)

    rows = []
    for u in res.units:
        r = row(u)
        if a.type and r["type"] != a.type:
            continue
        if a.scope and r["scope"] != a.scope:
            continue
        if a.enabled_only and r["enabled"] != "yes":
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['name']} {r['description']} {r['exec_start']}"):
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
    en = sum(1 for r in rows if r["enabled"] == "yes")
    fl = sum(1 for r in rows if r["notable"])
    print(f"linux_units: {len(res.units)} unit(s) -> {len(rows)} shown "
          f"({en} enabled), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
