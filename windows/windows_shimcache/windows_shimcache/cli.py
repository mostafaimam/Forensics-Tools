from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from windows_shimcache import __version__, tracelib
from windows_shimcache.extract import (
    from_blob_file,
    from_hive_file,
    looks_like_hive,
)
from windows_shimcache.shimcache import ShimCacheError, detect_format

COLUMNS = ["position", "last_modified_utc", "executed", "path", "control_set",
           "data_size", "source_file"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _row(e, source: str) -> dict:
    return {
        "position": e.position,
        "last_modified_utc": e.last_modified_iso,
        "executed": "" if e.executed is None else ("yes" if e.executed else "no"),
        "path": e.path,
        "control_set": e.control_set,
        "data_size": e.data_size,
        "source_file": source,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_shimcache",
        description="Parse the Windows AppCompatCache / ShimCache - evidence of "
                    "program presence (and, on Windows 7/8, execution). Takes a "
                    "SYSTEM hive or a raw AppCompatCache value.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_shimcache SYSTEM --csv shimcache.csv\n"
            "  windows_shimcache appcompatcache.bin --json out.json\n"
            "  windows_shimcache SYSTEM --grep '\\\\temp\\\\|\\.tmp'\n"
        ),
    )
    p.add_argument("inputs", nargs="*", type=Path, metavar="FILE")
    p.add_argument("--registry", action="store_true",
                   help="read the live AppCompatCache from this running system")
    p.add_argument("--version", action="version",
                   version=f"windows_shimcache {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--grep", metavar="REGEX", help="keep only matching paths")
    p.add_argument("--executed-only", action="store_true",
                   help="Windows 7/8: keep only entries flagged executed")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from windows_shimcache.gui import run_gui
        return run_gui([str(x) for x in (args.inputs or [])])
    import re

    rx = None
    if args.grep:
        try:
            rx = re.compile(args.grep, re.IGNORECASE)
        except re.error as e:
            print(f"bad regex: {e}", file=sys.stderr)
            return 2

    rows: list[dict] = []
    parsed = 0

    if args.registry:
        try:
            import winreg

            from windows_shimcache.shimcache import parse as _parse
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache")
            blob = winreg.QueryValueEx(k, "AppCompatCache")[0]
            parsed += 1
            for e in _parse(bytes(blob), control_set="CurrentControlSet"):
                if rx and not rx.search(e.path):
                    continue
                if args.executed_only and e.executed is not True:
                    continue
                rows.append(_row(e, "<live registry>"))
        except (OSError, ImportError, ShimCacheError, ValueError) as e:
            print(f"! live registry: {e}", file=sys.stderr)

    if not args.inputs and not args.registry:
        print("error: give a SYSTEM hive / blob file, or --registry",
              file=sys.stderr)
        return 2

    ctx = tracelib.context(args, "windows_shimcache", __version__)
    try:
        ctx.limits.check_paths([str(f) for f in args.inputs])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for f in args.inputs:
        ctx.add_input(str(f))
    if args.registry:
        ctx.notes = (ctx.notes + " " if ctx.notes else "") + \
            "live-registry AppCompatCache included"

    for f in args.inputs:
        if not f.exists():
            print(f"! not found: {f}", file=sys.stderr)
            continue
        try:
            data = f.read_bytes()
            entries = (from_hive_file(f) if looks_like_hive(data)
                       else from_blob_file(f))
            fmt = "" if looks_like_hive(data) else detect_format(data)
        except (ShimCacheError, OSError, ValueError) as e:
            print(f"! {f}: {e}", file=sys.stderr)
            continue
        parsed += 1
        for e in entries:
            if rx and not rx.search(e.path):
                continue
            if args.executed_only and e.executed is not True:
                continue
            rows.append(_row(e, str(f)))

    if args.csv:
        tracelib.write_csv(rows, args.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if args.json:
        tracelib.write_json(rows, args.json, ctx,
                            confidence="medium", tz="utc-native")
    if not args.quiet and not (args.csv or args.json):
        print(_render(rows))

    _mpath = ctx.finish(outputs=[args.csv, args.json])
    print(f"windows_shimcache {__version__}: {len(rows)} entr(y|ies) from "
          f"{parsed} file(s)", file=sys.stderr)
    return 1 if parsed == 0 else 0


def _write_csv(rows, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(v) for k, v in r.items()})


def _render(rows, limit: int = 200) -> str:
    out = io.StringIO()
    cols = [("position", 8), ("last_modified_utc", 27), ("executed", 8),
            ("path", 70)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 115 + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r[h])[: w - 1] + "…") if len(str(r[h])) > w
            else str(r[h]).ljust(w) for h, w in cols).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
