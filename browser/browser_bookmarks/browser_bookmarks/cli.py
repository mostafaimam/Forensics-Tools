from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_bookmarks import __version__
from browser_bookmarks.analyze import analyze
from browser_bookmarks.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_bookmarks",
        description="The bookmark tree with added / modified times. Reads the "
                    "Chromium 'Bookmarks' JSON (diffed against "
                    "'Bookmarks.bak' to surface deleted entries) and Firefox "
                    "'moz_bookmarks' in places.sqlite. Read-only, WAL-safe. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_bookmarks ./Bookmarks\n"
                "  browser_bookmarks /mnt/evidence/Users --csv bookmarks.csv\n"
                "  browser_bookmarks ./profile --grep 'onion|drive'\n"
                "  browser_bookmarks ./Users --notable-only\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_bookmarks {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--browser")
    p.add_argument("--folder", help="only bookmarks whose folder path contains this")
    p.add_argument("--grep", metavar="REGEX", help="match title / URL / folder")
    p.add_argument("--deleted-only", action="store_true",
                   help="only entries found only in Bookmarks.bak")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_bookmarks.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a Bookmarks / places.sqlite store or a folder "
                             "is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = analyze([str(p) for p in a.paths])

    rows = []
    for bm in res.bookmarks:
        r = row(bm)
        if a.deleted_only and r["source"] != "bak-only":
            continue
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.folder and a.folder.lower() not in r["folder"].lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['title']} {r['url']} {r['folder']}"):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    deleted_n = sum(1 for r in rows if r["source"] == "bak-only")
    fl = sum(1 for r in rows if r["notable"])
    print(f"browser_bookmarks: {res.stores} store(s) -> {len(rows)} "
          f"bookmark(s) ({deleted_n} deleted), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
