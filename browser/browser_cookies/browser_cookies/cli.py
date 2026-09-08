from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_cookies import __version__, tracelib
from browser_cookies.output import columns, render, row
from browser_cookies.scan import scan

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_cookies",
        description="Cookies from Chrome / Edge / Firefox / Safari stores on a "
                    "disk image - host, expiry, flags, session/auth-token "
                    "detection. Read-only and WAL-safe; values are metadata "
                    "only unless --with-values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  browser_cookies /mnt/evidence/Users --csv cookies.csv\n"
            "  browser_cookies /cases/img/Users --auth-only --json sessions.json\n"
            "  browser_cookies ./Cookies --host example.com\n"
            "  browser_cookies /mnt/img/Users --notable-only --min-severity high\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_cookies {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--browser", metavar="NAME")
    p.add_argument("--host", metavar="SUBSTR",
                   help="keep cookies whose host matches this substring")
    p.add_argument("--name", metavar="SUBSTR")
    p.add_argument("--auth-only", action="store_true",
                   help="only session / authentication cookies")
    p.add_argument("--session-only", action="store_true",
                   help="only session cookies (no persistent expiry)")
    p.add_argument("--secure-only", action="store_true")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX")
    p.add_argument("--with-values", action="store_true",
                   help="include plaintext values (Firefox / Safari only)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_cookies.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a path (image mount, profile dir, or a Cookies "
                             "file) is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    ctx = tracelib.context(a, "browser_cookies", __version__)
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

    res = scan([str(p) for p in a.paths], browser=a.browser, progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    rows = []
    for c in res.cookies:
        r = row(c, a.with_values)
        if a.host and a.host.lower() not in r["host"].lower():
            continue
        if a.name and a.name.lower() not in r["name"].lower():
            continue
        if a.auth_only and "session/auth-cookie" not in r["notable"]:
            continue
        if a.session_only and r["session"] != "yes":
            continue
        if a.secure_only and r["secure"] != "yes":
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["host"] + " " + r["name"]):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, columns(a.with_values), ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    hosts = len({r["host"] for r in rows})
    auth = sum(1 for r in rows if "session/auth-cookie" in r["notable"])
    fl = sum(1 for r in rows if r["notable"])
    for _e in res.errors:
        ctx.error("source-error", _e)
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_cookies: {res.stores} store(s) -> {len(rows)} cookie(s) "
          f"across {hosts} host(s), {auth} session/auth, {fl} flagged",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
