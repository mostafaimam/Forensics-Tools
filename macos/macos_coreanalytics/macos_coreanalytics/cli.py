from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_coreanalytics import __version__, tracelib
from macos_coreanalytics.collect import collect

COLUMNS = ["timestamp", "event_name", "app", "launches",
           "foreground_seconds", "active_seconds", "extra", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_coreanalytics",
        description="Parse CoreAnalytics (.core_analytics) app-usage "
                    "aggregates: daily launch counts, foreground / active "
                    "time and hardware/OS context. Schema-tolerant - each "
                    "record's name, timestamp and counters are recovered by "
                    "content, and anything unrecognised is kept as JSON in "
                    "'extra'.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_coreanalytics /Library/Logs/DiagnosticReports "
                "--csv usage.csv\n"
                "  macos_coreanalytics Analytics-2026-03-16.core_analytics "
                "--app Safari\n"
                "  macos_coreanalytics ./reports --since 2026-03-01\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help=".core_analytics file(s), a DiagnosticReports "
                        "folder, or a mount root")
    p.add_argument("--version", action="version",
                   version=f"macos_coreanalytics {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--app", metavar="SUBSTR", help="match the app / bundle id")
    p.add_argument("--grep", metavar="REGEX",
                   help="match event name / app / extra")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from macos_coreanalytics.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "macos_coreanalytics", __version__)
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
        ctx.error("coreanalytics-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.app and a.app.lower() not in (r.get("app") or "").lower():
            continue
        t = r.get("timestamp") or ""
        if a.since and (not t or t[:10] < a.since):
            continue
        if a.until and (not t or t[:10] > a.until):
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "event_name", "app", "extra"))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="low", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(f"{r.get('timestamp') or '(no time)':<21} "
                  f"{r.get('app') or r.get('event_name') or '?':<32} "
                  f"launches={r.get('launches') or '-':<4} "
                  f"fg={r.get('foreground_seconds') or '-'}")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"macos_coreanalytics: {res.files} file(s) -> {len(rows)} "
          f"record(s)", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
