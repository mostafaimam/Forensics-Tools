from __future__ import annotations

import sys
import argparse
from pathlib import Path

from browser_localstorage import __version__, tracelib
from browser_localstorage.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_localstorage",
        description="From-scratch LevelDB reader for Chromium's Local "
                    "Storage and IndexedDB. Reads every key/value ever "
                    "written across a database's .log write-ahead-log and "
                    ".ldb SSTable files - not just the current live value, "
                    "so overwritten or deleted entries are recovered too. "
                    "Local Storage directories get the origin/key schema "
                    "applied (best-effort); IndexedDB and other LevelDB "
                    "directories are surfaced as raw key/value pairs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_localstorage \"Local Storage/leveldb\"\n"
                "  browser_localstorage ~/AppData/Local/Google/Chrome/User"
                " Data --csv rows.csv\n"
                "  browser_localstorage --gui\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a LevelDB directory, or a root to search "
                   "recursively for one")
    p.add_argument("--version", action="version",
                   version=f"browser_localstorage {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--origin", help="only rows from this origin "
                   "(substring match, local_storage rows only)")
    p.add_argument("--deleted-only", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_localstorage.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "browser_localstorage", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect([a.target])
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.origin:
        rows = [r for r in rows if a.origin.lower() in r["origin"].lower()]
    if a.deleted_only:
        rows = [r for r in rows if r["deleted"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = " [deleted]" if r["deleted"] else ""
            origin = f"{r['origin']}  " if r["origin"] else ""
            print(f"{r['store_kind']:<14} {origin}{r['key']!r} = "
                 f"{r['value']!r}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="no-timezone")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="no-timezone")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_localstorage: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
