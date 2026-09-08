from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_sessions import __version__
from browser_sessions.analyze import analyze
from browser_sessions.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_sessions",
        description="Reconstruct the browsing session open at last browser "
                    "close: Chromium SNSS 'Session_*' / 'Tabs_*' / 'Last "
                    "Session' and Firefox 'sessionstore.jsonlz4' (mozLz4 + a "
                    "bundled LZ4 decoder). One row per tab with window, "
                    "position, pinned state, current URL / title, history "
                    "depth and last-accessed time. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_sessions './Last Session'\n"
                "  browser_sessions /mnt/evidence/Users --csv tabs.csv\n"
                "  browser_sessions ./profile --closed-only\n"
                "  browser_sessions ./Users --grep 'mail|drive'\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_sessions {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--browser")
    p.add_argument("--closed-only", action="store_true",
                   help="only recently-closed tabs")
    p.add_argument("--open-only", action="store_true",
                   help="only tabs that were still open")
    p.add_argument("--grep", metavar="REGEX", help="match URL / title")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_sessions.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a session file or a folder is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = analyze([str(p) for p in a.paths])

    rows = []
    for t in res.tabs:
        r = row(t)
        if a.closed_only and not r["closed"]:
            continue
        if a.open_only and r["closed"]:
            continue
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['current_url']} {r['current_title']} {r['history']}"):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.findings), end="")

    op = sum(1 for r in rows if not r["closed"])
    cl = len(rows) - op
    fl = sum(1 for r in rows if r["notable"])
    print(f"browser_sessions: {res.files} file(s) -> {len(rows)} tab(s) "
          f"({op} open, {cl} closed), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
