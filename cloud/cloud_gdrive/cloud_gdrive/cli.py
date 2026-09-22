from __future__ import annotations

import sys
import argparse
from pathlib import Path

from cloud_gdrive import __version__, tracelib
from cloud_gdrive.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud_gdrive",
        description="Locate and generically inspect Google Drive for "
                    "Desktop sync-client metadata (metadata_sqlite_db, "
                    "snapshot.db): a schema-tolerant table dump - full "
                    "row fidelity, no claimed understanding of the "
                    "proprietary items/stable_ids schema beyond "
                    "conservative column-name hints.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  cloud_gdrive \"%LOCALAPPDATA%\\Google\\DriveFS\"\n"
                "  cloud_gdrive metadata_sqlite_db --csv rows.csv\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a DriveFS folder to search, or a specific "
                   "database file")
    p.add_argument("--version", action="version",
                   version=f"cloud_gdrive {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--table", help="substring filter on table name")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from cloud_gdrive.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "cloud_gdrive", __version__)
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
    if a.table:
        rows = [r for r in rows if a.table.lower() in r["table"].lower()]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(f"{r['table']:<16} {r['row_json'][:120]}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="unknown")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="low", tz="unknown")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"cloud_gdrive: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
