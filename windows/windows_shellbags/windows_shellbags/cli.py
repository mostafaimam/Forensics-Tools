from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_shellbags import __version__, tracelib
from windows_shellbags.analyze import analyze
from windows_shellbags.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_shellbags",
        description="Reconstruct the shellbag folder-access tree from "
                    "BagMRU / Bags in UsrClass.dat (and the older NTUSER.DAT "
                    "locations) under a mounted image or from a hive file "
                    "directly. One row per folder the user browsed in "
                    "Explorer: the full reconstructed path, the shell-item "
                    "type, the BagMRU key path + NodeSlot + last-written time "
                    "(folder last interacted), the folder's own created / "
                    "modified / accessed DOS timestamps and the $MFT entry + "
                    "sequence from the BEEF0004 block, and the MRUListEx "
                    "position. Flags removable / network / UNC paths, "
                    "browsing inside an archive or disk image, another user's "
                    "profile, AppData / Temp / ProgramData / $Recycle.Bin "
                    "paths and GUID-only entries. Pure standard library "
                    "(regf + shell-item parsers vendored).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_shellbags E:\\   (mounted image root)\n"
                "  windows_shellbags UsrClass.dat --csv shellbags.csv\n"
                "  windows_shellbags E:\\ --notable-only --min-severity high\n"
                "  windows_shellbags E:\\ --grep 'zip|\\\\\\\\'\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="mounted-image root, a user profile dir, or a "
                        "UsrClass.dat / NTUSER.DAT hive")
    p.add_argument("--version", action="version",
                   version=f"windows_shellbags {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", dest="item_type",
                   help="only this shell-item type (drive / directory / "
                        "known-folder / network / delegate)")
    p.add_argument("--grep", metavar="REGEX", help="match path / name")
    p.add_argument("--max-depth", type=int, default=0,
                   help="only folders at or above this tree depth")
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
        from windows_shellbags.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_shellbags", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for h in res.hives:
        ctx.add_input(h.split(" [", 1)[0])
    for e in res.errors:
        ctx.error("shellbag-error", e)
    if not res.hives:
        ctx.partial("no-bagmru", "no BagMRU tree found under the given path(s)")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for b in res.bags:
        r = row(b)
        if a.item_type and r["item_type"] != a.item_type:
            continue
        if a.max_depth and r["depth"] > a.max_depth:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['path']} {r['name']}"):
            continue
        rows.append(r)

    # shell-item DOS timestamps are local, no timezone; the key last-written
    # is a real FILETIME (UTC).
    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="mixed-local-and-utc")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="mixed-local-and-utc")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_shellbags: {len(res.bags)} folder(s) from "
          f"{len(res.hives)} hive(s) -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
