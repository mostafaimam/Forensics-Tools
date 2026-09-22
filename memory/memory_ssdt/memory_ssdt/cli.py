from __future__ import annotations

import sys
import argparse
from pathlib import Path

from memory_ssdt import __version__, tracelib
from memory_ssdt.collect import COLUMNS, scan_image


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_ssdt",
        description="Best-effort scan for SSDT-shaped function-pointer "
                    "tables in a Windows memory image. "
                    "KeServiceDescriptorTable is unexported on x64 with "
                    "no stable offset this project can resolve, and "
                    "PatchGuard prevents genuine runtime hooking of the "
                    "real table on modern builds - expect this to find "
                    "little or nothing on a typical Windows 10/11 x64 "
                    "image; that is the correct outcome, not a bug. "
                    "Instead, this finds candidate pointer arrays that "
                    "cluster within one plausible kernel image and "
                    "flags any entries that don't, as a possible-hook "
                    "lead requiring corroboration - see the README.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  memory_ssdt MEMORY.DMP --csv candidates.csv\n")
    p.add_argument("image", nargs="?", type=Path)
    p.add_argument("--version", action="version",
                   version=f"memory_ssdt {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--min-entries", type=int, default=64,
                   help="only report candidates with at least this many "
                   "entries (default: 64, reduces noise)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from memory_ssdt.gui import run_gui
        return run_gui([a.image] if a.image else [])
    if not a.image:
        build_parser().error("an image path is required (or --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "memory_ssdt", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))

    res = scan_image(str(a.image), min_entries=a.min_entries)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['phys_offset']:<12} entries={r['entry_count']:<6} "
                 f"outliers={r['outlier_count']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="heuristic", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"memory_ssdt: {len(res.rows)} candidate table(s)",
         file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
