from __future__ import annotations

import sys
import argparse
from pathlib import Path

from macos_unifiedlog import __version__, tracelib
from macos_unifiedlog.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_unifiedlog",
        description="Best-effort Apple Unified Logging (.tracev3) chunk "
                    "reader: enumerates every top-level and ChunkSet "
                    "-nested chunk, best-effort LZ4-decompresses "
                    "ChunkSet payloads (self-verified, not blindly "
                    "trusted), and carves printable strings out of "
                    "Firehose/Oversize/StateDump/SimpleDump chunks. Does "
                    "NOT resolve format strings against uuidtext/dsc or "
                    "produce fully formatted log lines - see the "
                    "README's Confidence & Validation section.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  macos_unifiedlog 0123456789ABCDEF.tracev3 "
              "--csv rows.csv\n")
    p.add_argument("target", type=Path, help="a .tracev3 file")
    p.add_argument("--version", action="version",
                   version=f"macos_unifiedlog {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--strings-only", action="store_true",
                   help="only print carved strings, not the chunk "
                   "inventory")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from macos_unifiedlog.gui import run_gui
        return run_gui([str(a.target)] if a.target else [])
    if not a.target:
        build_parser().error("a target .tracev3 file is required (or "
                            "--gui)")
    if not a.target.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_unifiedlog", __version__)
    try:
        ctx.limits.check_paths([str(a.target)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.target))

    res = collect(str(a.target))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.strings_only:
        rows = [r for r in rows if r["kind"] == "string"]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            if r["kind"] == "chunk":
                print(f"chunk  @{r['offset']:<10} {r['tag_name']:<12} "
                     f"len={r['length']}")
            else:
                print(f"string @{r['offset']:<10} {r['tag_name']:<12} "
                     f"{r['value']!r}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="low", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"macos_unifiedlog: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
