from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_history import __version__, tracelib
from browser_history.flags import severity
from browser_history.output import COLUMNS, render, row
from browser_history.scan import scan

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _norm_date(s: str, *, end: bool = False) -> str:
    s = (s or "").strip().replace(" ", "T")
    if len(s) == 10:
        s += "T23:59:59" if end else "T00:00:00"
    if s and not s.endswith("Z"):
        s += "Z"
    return s


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_history",
        description="Web history, downloads and typed URLs from a disk image "
                    "or a live system - Chromium family, Firefox / Tor, "
                    "Safari - read-only and WAL-safe. Suspicious URLs are "
                    "flagged.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  browser_history /mnt/evidence/Users --html not-shown --csv h.csv\n"
            "  browser_history /cases/img --browser chrome --typed-only\n"
            "  browser_history ./History --downloads-only --json dl.json\n"
            "  browser_history /mnt/img/Users --grep 'mega|anonfiles' \\\n"
            "      --from 2026-08-01 --to 2026-08-31\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_history {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--browser", metavar="NAME",
                   help="keep only this browser (chrome / edge / firefox / …)")
    p.add_argument("--profile", metavar="SUBSTR",
                   help="keep only profiles whose path matches")
    p.add_argument("--kind", choices=["visit", "download", "search"],
                   action="append", default=[])
    p.add_argument("--typed-only", action="store_true",
                   help="only URLs the user typed / searched")
    p.add_argument("--downloads-only", action="store_true")
    p.add_argument("--notable-only", action="store_true",
                   help="only entries with at least one heuristic flag")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX",
                   help="keep rows whose URL / title matches (case-insensitive)")
    p.add_argument("--from", dest="dt_from", metavar="DATE")
    p.add_argument("--to", dest="dt_to", metavar="DATE")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_history.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a path (disk image mount, profile dir, or a "
                             "History / places.sqlite file) is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "browser_history", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in a.paths:
        ctx.add_input(str(p))

    grep = re.compile(a.grep, re.I) if a.grep else None
    prog = None
    if not a.quiet:
        def prog(done, total):  # noqa: E306
            sys.stderr.write(f"\r  {done}/{total} stores")
            sys.stderr.flush()

    res = scan([str(p) for p in a.paths], browser=a.browser,
               since=_norm_date(a.dt_from) if a.dt_from else "",
               until=_norm_date(a.dt_to, end=True) if a.dt_to else "",
               progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for e in res.entries:
        r = row(e)
        if a.profile and a.profile.lower() not in r["profile"].lower():
            continue
        if a.kind and r["kind"] not in a.kind:
            continue
        if a.downloads_only and r["kind"] != "download":
            continue
        if a.typed_only and r["typed"] != "yes":
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["url"] + " " + r["title"]):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    v = sum(1 for r in rows if r["kind"] == "visit")
    d = sum(1 for r in rows if r["kind"] == "download")
    s = sum(1 for r in rows if r["kind"] == "search")
    fl = sum(1 for r in rows if r["notable"])
    for _e in res.errors:
        ctx.error("source-error", _e)
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_history: {res.stores} store(s) -> {v} visits, "
          f"{d} downloads, {s} searches, {fl} flagged", file=sys.stderr)
    for err in res.errors:
        print(f"  ! {err}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
