from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_bam import __version__, tracelib
from windows_bam import flags as _flags
from windows_bam.bam import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["sid", "path", "raw_path", "last_run", "moderator", "control_set",
           "severity", "notable"]


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    out = []
    for rel in ("Windows/System32/config/SYSTEM", "System32/config/SYSTEM",
                "config/SYSTEM", "SYSTEM"):
        c = p / rel
        if c.is_file():
            out.append(c)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_bam",
        description="Background / Desktop Activity Moderator last-execution "
                    "data from a SYSTEM hive: one row per (user SID, "
                    "executable) with the last-run time (FILETIME, UTC), the "
                    "moderator (bam / dam) and the control set. \\Device\\ "
                    "paths are rewritten to <volN>\\. Flags executables in a "
                    "user-writable path, LOLBins, UNC paths and system-binary "
                    "name masquerades. Pure standard library (regf parser "
                    "vendored); read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_bam SYSTEM --csv bam.csv\n"
                "  windows_bam E:\\  (mounted image root)\n"
                "  windows_bam SYSTEM --sid S-1-5-21-... --json u.json\n"
                "  windows_bam SYSTEM --notable-only --min-severity high\n"))
    p.add_argument("path", type=Path, help="a SYSTEM hive or a mounted root")
    p.add_argument("--version", action="version",
                   version=f"windows_bam {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--sid", help="only this user SID")
    p.add_argument("--moderator", choices=["bam", "dam"])
    p.add_argument("--grep", metavar="REGEX", help="match the executable path")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
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
        from windows_bam.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_bam", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    hives = _discover(a.path)
    if not hives:
        print("no SYSTEM hive found under that path", file=sys.stderr)
        return 2

    all_rows = []
    sids: set = set()
    errors: list = []
    for h in hives:
        ctx.add_input(str(h))
        res = parse(h.read_bytes())
        errors += res.errors
        sids |= res.sids
        for e in res.entries:
            e.notable = _flags.flag(e)
            all_rows.append(e)
    for e in errors:
        ctx.error("hive-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for e in all_rows:
        r = e.row()
        r["severity"] = _flags.severity(e.notable)
        if a.sid and r["sid"] != a.sid:
            continue
        if a.moderator and r["moderator"] != a.moderator:
            continue
        if a.since and (not r["last_run"] or r["last_run"][:10] < a.since):
            continue
        if a.until and (not r["last_run"] or r["last_run"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["path"]):
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
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['last_run'] or '(no time)':<28} {r['moderator']:<4} "
                  f"{r['path']}{mark}")
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_bam: {len(all_rows)} entr(y/ies), {len(sids)} SID(s) -> "
          f"{len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
