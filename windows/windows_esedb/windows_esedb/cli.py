from __future__ import annotations

import argparse
import sys
from pathlib import Path

from windows_esedb import __version__, tracelib
from windows_esedb.coltypes import filetime
from windows_esedb.database import EseDatabase, EseError


def _serialise(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_esedb",
        description="Standalone, dependency-free ESE / JET (.edb) database "
                    "reader. Parses the header, the catalog (MSysObjects), "
                    "the B-trees and the long-value trees; decodes leaf "
                    "records via the fixed / variable / tagged data layout "
                    "(including the Vista+ extended tagged format and 7-bit "
                    "compression). Works on SRUDB.dat, WebCacheV01.dat, the "
                    "UAL *.mdb and Windows.edb. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_esedb SRUDB.dat --info\n"
                "  windows_esedb SRUDB.dat --list-tables\n"
                "  windows_esedb WebCacheV01.dat --table Containers "
                "--csv containers.csv\n"
                "  windows_esedb SRUDB.dat --table "
                "'{973F5D5C-1D90-4944-BE8E-24B94231A174}' --json net.json\n"))
    p.add_argument("path", type=Path, help="the ESE database file")
    p.add_argument("--version", action="version",
                   version=f"windows_esedb {__version__}")
    p.add_argument("--info", action="store_true",
                   help="print the header / catalog summary and exit")
    p.add_argument("--list-tables", action="store_true")
    p.add_argument("--all-tables", action="store_true",
                   help="with --list-tables, include the MSys* internal tables")
    p.add_argument("--table", help="dump this table")
    p.add_argument("--filetime-columns", default="",
                   help="comma-separated column names to render as FILETIME")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_esedb", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    try:
        db = EseDatabase.from_file(a.path)
    except EseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not db.info()["clean"]:
        ctx.partial("dirty-database", "the database was not cleanly shut "
                    "down; some pages may be inconsistent")

    if a.info or (not a.list_tables and not a.table):
        info = db.info()
        for k, v in info.items():
            print(f"{k:16} {v}")
        print("tables:")
        for n in db.all_table_names():
            print(f"  {n}")
        ctx.finish(outputs=[])
        return 0

    if a.list_tables:
        for n in (db.all_table_names() if a.all_tables else db.table_names):
            print(n)
        ctx.finish(outputs=[])
        return 0

    try:
        table = db.table(a.table)
    except EseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    ft_cols = {c.strip() for c in a.filetime_columns.split(",") if c.strip()}
    cols = [c.name for c in table.columns]
    rows = []
    for i, rec in enumerate(table.records()):
        if a.limit and i >= a.limit:
            break
        r = {}
        for k in cols:
            v = rec.get(k)
            if k in ft_cols and isinstance(v, int):
                v = filetime(v)
            r[k] = _serialise(v)
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, cols, ctx,
                           confidence="medium", tz="mixed")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="mixed")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(" | ".join(f"{k}={r[k]}" for k in cols if r[k] not in
                              (None, "")))

    ctx.finish(outputs=[a.csv, a.json])
    print(f"windows_esedb: {a.table} -> {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
