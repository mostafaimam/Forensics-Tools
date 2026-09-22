from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_callbacks import __version__, tracelib
from memory_callbacks.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_callbacks",
        description="Best-effort scan for kernel notification-callback "
                    "-array-shaped pointer tables (process/thread/image "
                    "-load and similar) in a Windows memory image. The "
                    "actual kernel globals are unexported with no "
                    "stable offset this project can resolve, so this "
                    "scans for the small, mostly-NULL, clustered-pointer "
                    "shape those tables have instead of locating a "
                    "specific named table - reported candidates and "
                    "flagged outliers are investigative leads, not "
                    "confirmed findings. See the README.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  memory_callbacks MEMORY.DMP --csv "
              "candidates.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--version", action="version",
                   version=f"memory_callbacks {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_callbacks.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_callbacks", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            reg, out = r['registered_count'], r['outlier_count']
            print(f"size={r['size']:<4} registered={reg:<3} "
                 f"outliers={out:<3} @{r['phys_offset']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="heuristic", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_callbacks: {len(res.rows)} candidate table(s)",
         file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
