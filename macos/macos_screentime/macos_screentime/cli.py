from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_screentime import __version__, tracelib
from macos_screentime.collect import collect
from macos_screentime.screentime import analyze, dump_entity

COLUMNS = ["date", "entity", "app", "duration_s", "start", "end", "device",
           "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_screentime",
        description="Parse Screen Time app / category daily usage totals "
                    "from RMAdminStore-Local.sqlite (a Core Data store): "
                    "per-app and per-category duration by day and device, "
                    "including usage synced from other Apple devices on the "
                    "same account. Usage-shaped Core Data entities are "
                    "found by column content (a bundle id, a duration or "
                    "start/end pair) via the Z_PRIMARYKEY entity map, not a "
                    "hard-coded table name, so it tolerates schema drift.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_screentime RMAdminStore-Local.sqlite --csv st.csv\n"
                "  macos_screentime ~/Library --app com.apple.mobilesafari\n"
                "  macos_screentime store.sqlite --list-entities\n"
                "  macos_screentime store.sqlite --dump-entity RMDAppUsage\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="RMAdminStore-Local.sqlite file(s), a folder, or a "
                        "mount root")
    p.add_argument("--version", action="version",
                   version=f"macos_screentime {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--app", metavar="SUBSTR")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--min-hours", type=float, default=0,
                   help="only rows with at least this many hours of usage")
    p.add_argument("--list-entities", action="store_true",
                   help="print every Core Data entity found and exit")
    p.add_argument("--dump-entity", metavar="NAME",
                   help="raw-dump one entity's rows (see --list-entities)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from macos_screentime.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    if a.list_entities or a.dump_entity:
        for p in a.paths:
            if not p.is_file():
                continue
            if a.dump_entity:
                rows = dump_entity(str(p), a.dump_entity)
                for r in rows[:2000]:
                    print(r)
                print(f"{len(rows)} row(s) from {a.dump_entity}",
                      file=sys.stderr)
            else:
                r = analyze(str(p))
                print(f"{p}:")
                for name, table in r.entities_seen:
                    tag = "  (usage-shaped)" if name in r.usage_entities \
                        else ""
                    print(f"  {name:<28} {table}{tag}")
        return 0

    ctx = tracelib.context(a, "macos_screentime", __version__)
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
        ctx.error("screentime-error", e)

    rows = []
    for r in res.rows:
        if a.app and a.app.lower() not in (r.get("app") or "").lower():
            continue
        d = r.get("date") or r.get("start") or ""
        if a.since and (not d or d[:10] < a.since):
            continue
        if a.until and (not d or d[:10] > a.until):
            continue
        if a.min_hours and (r.get("duration_s") or 0) < a.min_hours * 3600:
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            hrs = (r.get("duration_s") or 0) / 3600
            print(f"{r.get('date') or '?':<12} {r.get('app') or '?':<32} "
                  f"{hrs:>6.2f}h  ({r['entity']})")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"macos_screentime: {res.stores} store(s) -> {len(rows)} "
          f"usage row(s)", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
