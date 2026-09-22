from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_dumpfiles import __version__, tracelib
from memory_dumpfiles.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_dumpfiles",
        description="Reconstruct still-cache-resident file content from "
                    "a Windows memory image: pool-tag scan for "
                    "_FILE_OBJECT, then a self-verifying walk to any "
                    "surviving Cache Manager VACB views (Section "
                    "Object Pointers -> SharedCacheMap -> VACB). Field "
                    "offsets are found by scanning a plausible window "
                    "and keeping only a candidate whose own back "
                    "-pointer confirms it - not a hardcoded per-build "
                    "offset table. Gaps in a file's cached ranges are "
                    "reported as gaps, not silently filled.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  memory_dumpfiles MEMORY.DMP --dump-dir out\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--version", action="version",
                   version=f"memory_dumpfiles {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--dump-dir", type=Path,
                   help="write each recovered cache view to this "
                   "directory")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_dumpfiles.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_dumpfiles", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image),
                     dump_dir=str(a.dump_dir) if a.dump_dir else None)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['name']:<50} {r['view_size']!s:<10} "
                 f"{r['recovered']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="heuristic", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_dumpfiles: {len(res.rows)} row(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
