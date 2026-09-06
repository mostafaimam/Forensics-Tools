from __future__ import annotations

import argparse
import sys
from pathlib import Path

from memory_strings import __version__
from memory_strings.loader import MemoryImage, MemoryImageError
from memory_strings.output import render, row, write_csv, write_json
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
    return p


def _cmd_categories(a) -> int:
    for name in LIBRARY:
        print(f"  {name}")
    return 0


def _cmd_scan(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
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
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

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
    return {"scan": _cmd_scan, "categories": _cmd_categories}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
