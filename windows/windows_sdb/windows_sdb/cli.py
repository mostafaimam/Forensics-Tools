from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_sdb import __version__, flags, tracelib
from windows_sdb.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["kind", "name", "detail", "guid", "time", "dll", "module",
           "matching_files", "shims", "patches", "layers", "command_line",
           "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_sdb",
        description="Application Compatibility shim-database (.sdb) "
                    "forensics. Parses the tag tree and lists the database "
                    "(name, GUID, time), its shims and patches, and every "
                    "EXE entry with its matching files, shim / patch refs "
                    "and layers. Flags dangerous shims (InjectDll, "
                    "RedirectEXE, CorrectFilePaths, VirtualRegistry, "
                    "DisableNXShowUI, ...), custom binary patches, "
                    "non-standard shim DLLs and shims aimed at Windows "
                    "system binaries. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_sdb C:/Windows/AppPatch/sysmain.sdb --csv sdb.csv\n"
                "  windows_sdb custom.sdb --notable-only\n"
                "  windows_sdb E:\\Windows\\apppatch\\Custom --min-severity "
                "high\n"
                "  windows_sdb E:\\ --kind exe --grep svchost\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help=".sdb file(s), a folder of them, or a mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_sdb {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["database", "exe", "shim", "patch",
                                      "layer", "file"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / detail / matching files / shims / dll")
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
        from windows_sdb.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_sdb", __version__)
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
        ctx.error("sdb-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.kind and r["kind"] != a.kind:
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "name", "detail", "matching_files", "shims", "dll",
                "command_line"))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r.get("severity", "none") != \
                "none" else ""
            print(f"{r['kind']:<9} {r.get('name') or '(unnamed)'}{mark}")
            if r.get("detail"):
                print(f"    {r['detail']}")
            if r.get("matching_files"):
                print(f"    matches: {r['matching_files']}")
            if r.get("shims"):
                print(f"    shims: {r['shims']}")
            if r.get("patches"):
                print(f"    patches: {r['patches']}")
            if r.get("dll"):
                print(f"    dll: {r['dll']}")
            for nn in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_sdb: {res.databases} database(s) -> {len(rows)} record(s)"
          f", {fl} flagged (worst: {flags.worst(rows)})", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
