from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_autofill import __version__
from browser_autofill.analyze import analyze
from browser_autofill.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_autofill",
        description="Form-field history, saved address profiles and payment-"
                    "card metadata from the Chromium 'Web Data' store and "
                    "Firefox 'formhistory.sqlite'. Card numbers and "
                    "CVV / SSN-shaped values are never printed. Read-only, "
                    "WAL-safe. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_autofill './Web Data'\n"
                "  browser_autofill /mnt/evidence/Users --csv autofill.csv\n"
                "  browser_autofill ./profile --kind form-field --grep email\n"
                "  browser_autofill ./profile --notable-only\n"))
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"browser_autofill {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["form-field", "address", "card"])
    p.add_argument("--browser")
    p.add_argument("--grep", metavar="REGEX",
                   help="match field name / value / detail")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_autofill.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a Web Data / formhistory store or a folder "
                             "is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = analyze([str(p) for p in a.paths])

    rows = []
    for rec in res.records:
        r = row(rec)
        if a.kind and r["kind"] != a.kind:
            continue
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['name']} {r['value']} {r['detail']}"):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    kinds = ", ".join(f"{k}:{v}" for k, v in sorted(by_kind.items()))
    fl = sum(1 for r in rows if r["notable"])
    print(f"browser_autofill: {res.stores} store(s) -> {len(rows)} record(s) "
          f"({kinds or 'none'}), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
