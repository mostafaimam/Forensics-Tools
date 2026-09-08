from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_strings import __version__, tracelib
from memory_strings.loader import MemoryImage, MemoryImageError
from memory_strings.output import COLUMNS, render, row
from memory_strings.patterns import LIBRARY
from memory_strings.scan import scan


def _int(s: str) -> int:
    return int(s, 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_strings",
        description="Address-aware string extraction from a RAM dump (raw / "
                    "LiME / ELF core / Windows crash dump), with a built-in "
                    "pattern library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_strings scan mem.lime --classified --csv iocs.csv\n"
            "  memory_strings scan mem.lime --category url,email,btc\n"
            "  memory_strings scan mem.lime --grep 'password' --min-len 6\n"
            "  memory_strings scan MEMORY.DMP --physical-from 0x1000000 "
            "--physical-to 0x2000000\n"
            "  memory_strings categories\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"memory_strings {__version__}")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("categories", help="list the pattern library")
    gp = sub.add_parser("gui", help="open the graphical viewer")
    gp.add_argument("image", nargs="?")

    s = sub.add_parser("scan", help="extract strings")
    s.add_argument("image", type=Path)
    s.add_argument("--min-len", type=int, default=6)
    s.add_argument("--ascii-only", action="store_true")
    s.add_argument("--unicode-only", action="store_true")
    s.add_argument("--grep", metavar="REGEX")
    s.add_argument("--category", type=lambda x: {c.strip() for c in x.split(",")},
                   metavar="C,C", help="keep only these pattern categories")
    s.add_argument("--classified", action="store_true",
                   help="keep only strings that match some pattern")
    s.add_argument("--physical-from", type=_int)
    s.add_argument("--physical-to", type=_int)
    s.add_argument("--limit", type=int)
    s.add_argument("--csv", type=Path)
    s.add_argument("--json", type=Path)
    s.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(s)
    return p


def _cmd_categories(a) -> int:
    for name in LIBRARY:
        print(f"  {name}")
    return 0


def _cmd_scan(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "memory_strings", __version__)
    try:
        ctx.limits.check_paths([str(a.image)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.image))
    try:
        img = MemoryImage(a.image)
    except MemoryImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    hits = scan(img, min_len=a.min_len,
                want_ascii=not a.unicode_only,
                want_unicode=not a.ascii_only,
                grep=a.grep, categories=a.category,
                classified_only=a.classified,
                phys_from=a.physical_from, phys_to=a.physical_to,
                limit=a.limit)
    rows = [row(h) for h in hits]
    img.close()

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    _mpath = ctx.finish(outputs=[a.csv, a.json])
    by_cat = {}
    for r in rows:
        if r["category"]:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items()))
    print(f"memory_strings: {len(rows)} hit(s)"
          + (f" - {summary}" if summary else ""), file=sys.stderr)
    return 0 if rows else 1


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if a.cmd == "gui":
        from memory_strings.gui import run_gui
        return run_gui([a.image] if getattr(a, "image", None) else [])
    return {"scan": _cmd_scan, "categories": _cmd_categories}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
