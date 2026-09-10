from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_recentfilecache import __version__, flags, tracelib
from windows_recentfilecache.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["index", "name", "path", "file_mtime", "offset", "severity",
           "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_recentfilecache",
        description="Parse RecentFileCache.bcf (the Windows 7 pre-Amcache "
                    "program-execution artefact): a 20-byte header followed "
                    "by length-prefixed UTF-16 paths, one per executable the "
                    "Program Compatibility Assistant saw in the ~24 h before "
                    "the last inventory sweep. Flags executables in "
                    "writable directories, double extensions, script types "
                    "and LOLBins. The file has no internal timestamps - the "
                    "row carries the file's own mtime as a bound. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_recentfilecache RecentFileCache.bcf --csv rfc.csv\n"
                "  windows_recentfilecache C:/Windows/AppCompat/Programs "
                "--notable-only\n"
                "  windows_recentfilecache E:\\ --min-severity high\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="RecentFileCache.bcf file(s), a folder, or a mount "
                        "root")
    p.add_argument("--version", action="version",
                   version=f"windows_recentfilecache {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--grep", metavar="REGEX", help="match the path / name")
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
        from windows_recentfilecache.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_recentfilecache", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths)
    for s in res.sources:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("rfc-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r.get("path", "")):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="file-mtime")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="file-mtime")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r.get("severity", "none") != \
                "none" else ""
            print(f"[{r['index']:>3}] {r['path']}{mark}")
            for nn in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"      ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_recentfilecache: {res.files} file(s) -> {len(rows)} "
          f"entr(y/ies), {fl} flagged (worst: {flags.worst(rows)})",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
