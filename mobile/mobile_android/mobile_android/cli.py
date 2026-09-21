from __future__ import annotations

import sys
import argparse
from pathlib import Path

from mobile_android import __version__, tracelib
from mobile_android.collect import COLUMNS, collect
from mobile_android.extract import extract_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mobile_android",
        description="Read an `adb backup` (.ab) archive: header parse "
                    "(version, compression, encryption), zlib "
                    "decompression, and tar-member inventory (package, "
                    "category - files/db/shared-prefs - path, size, "
                    "mtime). --extract-dir pulls the files out with the "
                    "real apps/<package>/... tree preserved. v0.1 "
                    "handles unencrypted backups only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mobile_android backup.ab\n"
                "  mobile_android backup.ab --package com.example.app "
                "--csv files.csv\n"
                "  mobile_android backup.ab --extract-dir ./extracted\n"))
    p.add_argument("target", nargs="?", type=Path,
                   help="an .ab backup file")
    p.add_argument("--version", action="version",
                   version=f"mobile_android {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--package", help="substring filter on package name")
    p.add_argument("--category", choices=["f", "db", "sp", "r", "a",
                                          "manifest", "shared", "other"])
    p.add_argument("--extract-dir", type=Path,
                   help="extract every matching file, preserving the "
                   "tar tree")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mobile_android.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target .ab file is required (or --gui)")
    if not a.target.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "mobile_android", __version__)
    try:
        ctx.limits.check_paths([str(a.target)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.target))

    res = collect(str(a.target))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not res.rows and res.warnings:
        return 1

    rows = res.rows
    if a.package:
        rows = [r for r in rows if a.package.lower() in r["package"].lower()]
    if a.category:
        rows = [r for r in rows if r["category"] == a.category]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(f"{r['package'] or '-':<32} {r['category']:<10} "
                 f"{r['path']}  ({r['size']} bytes)")

    if a.extract_dir:
        names = {r["path"] for r in rows}
        n = extract_all(str(a.target), str(a.extract_dir),
                        name_filter=lambda n: n in names)
        print(f"mobile_android: extracted {n} file(s) to {a.extract_dir}",
             file=sys.stderr)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"mobile_android: {len(rows)} entr{'y' if len(rows)==1 else 'ies'}",
         file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
