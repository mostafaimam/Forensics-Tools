from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_logins import __version__, tracelib
from browser_logins.analyze import analyze
from browser_logins.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_logins",
        description="Saved-login METADATA from Chromium 'Login Data' and "
                    "Firefox 'logins.json': origin, realm, username, "
                    "created / last-used / password-changed times, use "
                    "count and the never-save list. Passwords are never "
                    "decrypted or printed - only whether an encrypted blob "
                    "exists. Read-only, WAL-safe. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_logins './Login Data'\n"
                "  browser_logins /mnt/evidence/Users --csv logins.csv\n"
                "  browser_logins ./profile --host github.com\n"
                "  browser_logins ./Users --notable-only\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_logins {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--browser")
    p.add_argument("--host", help="only credentials for this host (substring)")
    p.add_argument("--username", help="only this username (substring)")
    p.add_argument("--include-blacklist", action="store_true",
                   help="include never-save entries (excluded by default)")
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
        from browser_logins.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a Login Data / logins.json store or a folder "
                             "is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "browser_logins", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in a.paths:
        ctx.add_input(str(p))

    res = analyze([str(p) for p in a.paths])

    rows = []
    for lg in res.logins:
        r = row(lg)
        if r["blacklisted"] and not a.include_blacklist:
            continue
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.host and a.host.lower() not in r["host"].lower():
            continue
        if a.username and a.username.lower() not in r["username"].lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.findings), end="")

    bl = sum(1 for r in rows if r["blacklisted"])
    fl = sum(1 for r in rows if r["notable"])
    for _e in res.errors:
        ctx.error("source-error", _e)
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_logins: {res.stores} store(s) -> {len(rows)} record(s) "
          f"({bl} never-save), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
