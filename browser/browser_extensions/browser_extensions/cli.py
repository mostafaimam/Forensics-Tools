from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_extensions import __version__
from browser_extensions.output import COLUMNS, render, row, write_csv, write_json
from browser_extensions.scan import scan

_RANK = {"low": 0, "medium": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_extensions",
        description="List installed browser extensions (Chromium Preferences / "
                    "Secure Preferences, Firefox extensions.json) with their "
                    "permissions and install source. Sideloaded, unsigned and "
                    "over-permissioned extensions are flagged.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  browser_extensions /mnt/evidence/Users --csv extensions.csv\n"
            "  browser_extensions /cases/img/Users --sideloaded-only\n"
            "  browser_extensions ./Preferences --min-risk high --json x.json\n"
            "  browser_extensions /mnt/img/Users --perm nativeMessaging\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_extensions {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--browser", metavar="NAME")
    p.add_argument("--enabled-only", action="store_true")
    p.add_argument("--sideloaded-only", action="store_true",
                   help="only extensions not installed from the web store")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-risk", choices=["low", "medium", "high"])
    p.add_argument("--perm", action="append", default=[], metavar="NAME",
                   help="keep extensions holding this permission (repeatable)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / id / description")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_extensions.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a path (image mount, profile dir, or a "
                             "Preferences / extensions.json file) is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

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
    for e in res.extensions:
        r = row(e)
        if a.enabled_only and r["enabled"] != "yes":
            continue
        if a.sideloaded_only and (r["from_webstore"] == "yes"
                                  or r["install_source"] in
                                  ("webstore", "component", "builtin",
                                   "system")):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_risk and _RANK[r["risk"]] < _RANK[a.min_risk]:
            continue
        if a.perm and not any(
                pm.lower() in (r["api_permissions"] + " "
                               + r["host_permissions"]).lower()
                for pm in a.perm):
            continue
        if grep and not grep.search(
                r["name"] + " " + r["ext_id"] + " "
                + (e.description or "")):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    hi = sum(1 for r in rows if r["risk"] == "high")
    side = sum(1 for r in rows if r["notable"] and "sideload"
               in r["notable"])
    print(f"browser_extensions: {res.stores} store(s) -> {len(rows)} "
          f"extension(s), {hi} high-risk, {side} sideloaded", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
