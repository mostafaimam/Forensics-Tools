from __future__ import annotations

import sys
import argparse
from pathlib import Path

from mounting_vsc import __version__, tracelib
from mounting_vsc.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_vsc",
        description="Best-effort Volume Shadow Copy (VSS) discovery: "
                    "scans a volume/image for the VSS identifier GUID "
                    "(a well-established constant) and reports candidate "
                    "FILETIME/GUID fields found nearby. Does NOT mount "
                    "or reconstruct snapshot content - the block "
                    "-remapping logic needed for that is reverse "
                    "-engineered-only and unverified here; see the "
                    "README's Confidence & Validation section.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  mounting_vsc \\\\.\\C: --csv hits.csv\n")
    p.add_argument("target", type=Path,
                   help="a raw volume device path or disk-image file")
    p.add_argument("--version", action="version",
                   version=f"mounting_vsc {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mounting_vsc.gui import run_gui
        return run_gui([str(a.target)] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")
    if not a.target.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "mounting_vsc", __version__)
    try:
        ctx.limits.check_paths([str(a.target)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.target))

    res = collect(str(a.target))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['hit_offset']:<10} {r['kind']:<14} "
                 f"@{r['field_offset']:<10} {r['value']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="utc")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="low", tz="utc")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"mounting_vsc: {len(res.rows)} row(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
