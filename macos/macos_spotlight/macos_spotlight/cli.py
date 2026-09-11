from __future__ import annotations

import sys
import argparse
from pathlib import Path

from macos_spotlight import __version__, tracelib
from macos_spotlight.collect import COLUMNS, collect
from macos_spotlight.patterns import LIBRARY


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_spotlight",
        description="Carve Spotlight metadata artifacts (kMDItem* attribute "
                    "names, UTIs, download-provenance URLs, bundle "
                    "identifiers, paths) out of a store.db file, or a "
                    ".spotlight-V100 directory tree. This does not decode "
                    "the store's undocumented record/block format; it "
                    "extracts and classifies ASCII/UTF-16LE string runs, "
                    "which recovers real signal even from a deleted or "
                    "partially-overwritten store. See the README for scope.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_spotlight store.db\n"
                "  macos_spotlight /Volumes/Macintosh\\ HD/.Spotlight-V100 "
                "--csv hits.csv\n"
                "  macos_spotlight store.db --category url,bundle_id\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="store.db file, or a directory to search recursively")
    p.add_argument("--version", action="version",
                   version=f"macos_spotlight {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--list-categories", action="store_true")
    p.add_argument("-n", "--min-len", type=int, default=6)
    p.add_argument("-e", "--encoding", default="ascii,utf-16le",
                   help="comma list of ascii,utf-16le (default both)")
    p.add_argument("--category", metavar="A,B",
                   help="only these categories (default: all)")
    p.add_argument("--hex", action="store_true",
                   help="print offsets in hexadecimal")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.list_categories:
        for name in sorted(LIBRARY):
            print(name)
        return 0
    if a.gui:
        from macos_spotlight.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    cats = None
    if a.category:
        cats = [c.strip() for c in a.category.split(",") if c.strip()]
        bad = [c for c in cats if c not in LIBRARY]
        if bad:
            build_parser().error(f"unknown categor{'y' if len(bad)==1 else 'ies'}: "
                                 f"{', '.join(bad)}. See --list-categories.")
    encs = tuple(e.strip() for e in a.encoding.split(",") if e.strip())

    ctx = tracelib.context(a, "macos_spotlight", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    try:
        res = collect([a.target], min_len=a.min_len, encodings=encs,
                      categories=cats, hex_offset=a.hex)
    except PermissionError:
        print(f"error: cannot read {a.target}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not a.quiet and not (a.csv or a.json):
        for r in res.rows:
            print(f"{r['offset']}\t[{r['category']}]\t{r['text']}")

    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="heuristic", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"macos_spotlight: {len(res.sources)} store file(s), "
          f"{len(res.rows)} hit(s)", file=sys.stderr)
    return 0 if res.rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
