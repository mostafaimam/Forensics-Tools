from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from windows_recycle import __version__
from windows_recycle.output import (
    render_table,
    write_csv,
    write_json,
    write_jsonl,
)
from windows_recycle.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_recycle",
        description="Parse Windows Recycle Bin artefacts ($I / $R metadata and "
                    "the legacy INFO2 / INFO index) into CSV / JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_recycle \"C:\\$Recycle.Bin\" --csv deleted.csv\n"
            "  windows_recycle E:\\evidence\\collection --json deleted.json\n"
            "  windows_recycle \"$IA1B2C3.txt\" \"D:\\dump\\INFO2\"\n"
        ),
    )
    p.add_argument("paths", nargs="+", metavar="PATH",
                   help="$I file, INFO2/INFO file, $R content file, or a "
                        "directory to search recursively")
    p.add_argument("--version", action="version",
                   version=f"windows_recycle {__version__}")
    p.add_argument("--csv", metavar="FILE", type=Path, help="write a CSV report")
    p.add_argument("--json", metavar="FILE", type=Path, help="write a JSON report")
    p.add_argument("--jsonl", metavar="FILE", type=Path,
                   help="write a JSON-lines report")
    p.add_argument("--no-recurse", action="store_true",
                   help="do not descend into sub-directories")
    p.add_argument("--include-inactive", action="store_true",
                   help="also emit INFO2 slots marked as removed from the bin")
    p.add_argument("--errors-only", action="store_true",
                   help="only show records that failed to parse")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the console table (use with --csv/--json)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    result = scan(args.paths, recursive=not args.no_recurse)
    records = result.records

    if not args.include_inactive:
        records = [r for r in records if r.active or r.parse_error or r.warnings]
    if args.errors_only:
        records = [r for r in records if r.parse_error]

    records.sort(key=lambda r: (r.deleted_utc or datetime.min.replace(
        tzinfo=timezone.utc), r.original_path))

    errors = sum(1 for r in records if r.parse_error)
    real = [r for r in records if not r.parse_error]

    wrote = []
    if args.csv:
        write_csv(records, args.csv)
        wrote.append(str(args.csv))
    if args.json:
        write_json(records, args.json)
        wrote.append(str(args.json))
    if args.jsonl:
        write_jsonl(records, args.jsonl)
        wrote.append(str(args.jsonl))

    if not args.quiet:
        print(render_table(records))

    summary = (
        f"windows_recycle {__version__}: {result.artefacts_parsed} artefact file(s), "
        f"{len(real)} deleted item(s), {result.orphan_content} orphan content "
        f"file(s), {errors} parse error(s)"
    )
    print(summary, file=sys.stderr)
    for w in wrote:
        print(f"  wrote {w}", file=sys.stderr)

    if errors and not real:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
