from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

from windows_amcache import __version__
from windows_amcache.amcache import parse
from windows_amcache.hive import HiveError

COLUMNS = ["category", "name", "path", "sha1", "size", "publisher", "product",
           "version", "program_id", "link_date", "install_date",
           "driver_company", "driver_signed", "key_last_written_utc", "key_path"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_amcache",
        description="Parse Amcache.hve - the application-compatibility "
                    "inventory: executables (with SHA-1), installed programs "
                    "and drivers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_amcache Amcache.hve --csv amcache.csv\n"
            "  windows_amcache Amcache.hve --category file --grep '\\\\temp\\\\'\n"
            "  windows_amcache Amcache.hve --with-sha1 --json files.json\n"
        ),
    )
    p.add_argument("hive", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"windows_amcache {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--category", type=lambda s: {x.strip() for x in s.split(",")},
                   default=None, metavar="file,program,driver")
    p.add_argument("--grep", metavar="REGEX",
                   help="keep only rows whose path / name matches")
    p.add_argument("--with-sha1", action="store_true",
                   help="keep only records that carry a SHA-1")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        from windows_amcache.gui import run_gui
        return run_gui([str(args.hive)] if args.hive else [])
    if not args.hive:
        build_parser().error("a hive path is required (or use --gui)")
    if not args.hive.exists():
        print(f"hive not found: {args.hive}", file=sys.stderr)
        return 2

    rx = None
    if args.grep:
        try:
            rx = re.compile(args.grep, re.IGNORECASE)
        except re.error as e:
            print(f"bad regex: {e}", file=sys.stderr)
            return 2

    try:
        records = parse(args.hive.read_bytes())
    except HiveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    rows = []
    for r in records:
        if args.category and r.category not in args.category:
            continue
        row = r.as_row()
        if args.with_sha1 and not row["sha1"]:
            continue
        if rx and not (rx.search(str(row["path"])) or rx.search(str(row["name"]))):
            continue
        rows.append(row)

    rows.sort(key=lambda r: (r["category"], str(r["name"]).lower()))

    if args.csv:
        with args.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel",
                               extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2, default=str),
                             encoding="utf-8")
    if not args.quiet and not (args.csv or args.json):
        print(_render(rows))

    by_cat = {}
    for r in rows:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    with_sha1 = sum(1 for r in rows if r["sha1"])
    print(f"windows_amcache {__version__}: {len(rows)} record(s) "
          f"({', '.join(f'{v} {k}' for k, v in sorted(by_cat.items()))}), "
          f"{with_sha1} with SHA-1", file=sys.stderr)
    return 0 if records else 1


def _render(rows, limit: int = 200) -> str:
    out = io.StringIO()
    cols = [("category", 9), ("name", 34), ("sha1", 42), ("path", 50)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 135 + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r.get(h, ""))[: w - 1] + "…") if len(str(r.get(h, ""))) > w
            else str(r.get(h, "")).ljust(w) for h, w in cols).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
