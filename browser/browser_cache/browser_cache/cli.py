from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_cache import __version__, tracelib
from browser_cache.analyze import analyze
from browser_cache.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_cache",
        description="List and extract cached HTTP responses from the Chromium "
                    "Simple Cache (Cache/Cache_Data/<hash>_0) and the Firefox "
                    "cache2 store (cache2/entries/<sha1>). Every object: URL, "
                    "status, content-type, size, and request / response / "
                    "fetched / expiry times. --extract writes the bodies "
                    "(gzip / deflate decoded) with a SHA-256 each. Read-only. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_cache ./Cache\n"
                "  browser_cache /mnt/evidence/Users --csv cache.csv\n"
                "  browser_cache ./Cache --extract ./bodies --grep '\\.js$'\n"
                "  browser_cache ./cache2 --notable-only --min-severity high\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_cache {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="write each cached body into this directory")
    p.add_argument("--no-decode", action="store_true",
                   help="keep bodies gzip / deflate encoded")
    p.add_argument("--min-size", type=int, default=0, metavar="BYTES")
    p.add_argument("--browser")
    p.add_argument("--content-type", help="substring match on content-type")
    p.add_argument("--grep", metavar="REGEX", help="match the URL")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_cache.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a cache directory or entry file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "browser_cache", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in a.paths:
        ctx.add_input(str(p))

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = analyze([str(p) for p in a.paths],
                  extract_dir=str(a.extract) if a.extract else None,
                  min_size=a.min_size, decode=not a.no_decode)

    rows = []
    for e in res.entries:
        r = row(e)
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.content_type and a.content_type.lower() not in \
                r["content_type"].lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["url"]):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    if a.extract and not a.quiet:
        print(f"  extracted {res.extracted} body(ies) -> {a.extract}",
              file=sys.stderr)
    fl = sum(1 for r in rows if r["notable"])
    for _e in res.errors:
        ctx.error("source-error", _e)
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_cache: {res.stores} store(s) -> {len(rows)} cached "
          f"object(s), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
