from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_timers import __version__, tracelib
from memory_timers.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_timers",
        description="Enumerate Windows kernel timers (KTIMER, x64) from "
                    "a memory image via structural validation of the "
                    "documented DISPATCHER_HEADER/KTIMER layout - no "
                    "kernel symbols or global-list-head address needed. "
                    "Reports timer type, signal state, due time, DPC "
                    "pointer, and period.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  memory_timers MEMORY.DMP --csv timers.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--version", action="version",
                   version=f"memory_timers {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--periodic-only", action="store_true",
                   help="only timers with a non-zero period")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_timers.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_timers", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.periodic_only:
        rows = [r for r in rows if r["period_ms"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(f"{r['phys_offset']:<12} {r['timer_type']:<26} "
                 f"{r['state']:<13} period={r['period_ms']}ms  "
                 f"{r['due_time']}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_timers: {len(rows)} timer(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
