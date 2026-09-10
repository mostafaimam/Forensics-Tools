from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_installhistory import __version__, tracelib
from macos_installhistory import flags as _flags
from macos_installhistory.parse import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["date", "kind", "name", "version", "package_ids", "process",
           "content_type", "prefix", "pkg_file", "correlated", "severity",
           "source", "notable"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_installhistory",
        description="Parse InstallHistory.plist (the install-event timeline) "
                    "and /private/var/db/receipts/*.plist (one receipt per "
                    "installed package) from a mounted macOS volume or a "
                    "live root, and correlate them. One row per record: "
                    "date, name, version, package identifiers, the "
                    "installing process, the content type, the install "
                    "prefix and the .pkg file name. Flags installs by an "
                    "unusual / scripting process, packages from a download "
                    "folder, configuration profiles and receipts / events "
                    "with no counterpart. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_installhistory /Volumes/Macintosh\\ HD --csv ih.csv\n"
                "  macos_installhistory InstallHistory.plist --json ih.json\n"
                "  macos_installhistory /mnt/mac --kind receipt "
                "--notable-only\n"
                "  macos_installhistory /mnt/mac --min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a mounted macOS volume, or an InstallHistory.plist")
    p.add_argument("--version", action="version",
                   version=f"macos_installhistory {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["history", "receipt"])
    p.add_argument("--process", help="substring match on the install process")
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / package ids / pkg file")
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
        from macos_installhistory.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_installhistory", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    res = collect(str(a.path))
    for e in res.errors:
        ctx.error("install-error", e)
    if res.receipt_count == 0:
        ctx.partial("no-receipts", "no /var/db/receipts found - correlation "
                    "with the on-disk receipts is unavailable")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for rec in res.records:
        r = rec.row()
        r["severity"] = _flags.severity(rec.notable)
        if a.kind and r["kind"] != a.kind:
            continue
        if a.process and a.process.lower() not in r["process"].lower():
            continue
        if a.since and (not r["date"] or r["date"][:10] < a.since):
            continue
        if a.until and (not r["date"] or r["date"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((r["name"], r["package_ids"],
                                              r["pkg_file"]))):
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
            print(f"{r['date'] or '(no date)':<21} {r['kind']:<8} "
                  f"{r['name']} {r['version']}  [{r['process']}]{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_installhistory: {res.history_count} history + "
          f"{res.receipt_count} receipt(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
