from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_wmi import __version__, flags, tracelib
from windows_wmi.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["type", "class", "name", "namespace", "action_kind", "action",
           "query", "filter", "consumer", "offset", "live", "severity",
           "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_wmi",
        description="WMI repository persistence forensics. Scans OBJECTS.DATA "
                    "(MAPPING*.MAP flags live pages) for the event-"
                    "subscription triad: __EventFilter WQL queries, "
                    "*EventConsumer actions (command line, script, log, "
                    "SMTP) and the __FilterToConsumerBinding that arms them. "
                    "Flags LOLBin / encoded / writable-path consumers, "
                    "in-memory script consumers and non-default namespaces. "
                    "Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_wmi C:/Windows/System32/wbem/Repository --csv "
                "wmi.csv\n"
                "  windows_wmi OBJECTS.DATA --type consumer --notable-only\n"
                "  windows_wmi E:\\ --min-severity high --json wmi.json\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="the Repository folder, an OBJECTS.DATA file, or a "
                        "mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_wmi {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", choices=["filter", "consumer", "binding"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match name / query / action / namespace")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--live-only", action="store_true",
                   help="only records on mapped (live) pages")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_wmi.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_wmi", __version__)
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
        ctx.error("wmi-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.type and r["type"] != a.type:
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.live_only and not r.get("live"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "name", "query", "action", "namespace"))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="n/a")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r.get("severity", "none") != \
                "none" else ""
            stale = "" if r.get("live") else "  (stale page)"
            print(f"{r['type']:<9} {r['class']:<28} "
                  f"{r.get('name') or '(no name)'}{mark}{stale}")
            if r.get("namespace"):
                print(f"    ns: {r['namespace']}")
            if r.get("query"):
                print(f"    query: {r['query'][:200]}")
            if r.get("action"):
                print(f"    action: {r['action'][:200]}")
            if r["type"] == "binding":
                print(f"    filter={r.get('filter')}  "
                      f"consumer={r.get('consumer')}")
            for n in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_wmi: {res.repos} repo(s) -> {res.filters} filter(s), "
          f"{res.consumers} consumer(s), {res.bindings} binding(s); "
          f"{len(rows)} shown, {fl} flagged (worst: {flags.worst(rows)})",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
