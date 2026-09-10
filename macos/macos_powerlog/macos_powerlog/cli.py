from __future__ import annotations

import argparse
import json as _json
import re
import sys
from pathlib import Path

from macos_powerlog import __version__, tracelib
from macos_powerlog import flags as _flags
from macos_powerlog.parse import collect, dump_table, list_tables

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["timestamp", "kind", "value", "detail", "latitude", "longitude",
           "table", "severity", "source", "notable"]

_NAMES = ("CurrentPowerlog.PLSQL",)


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    out = []
    for n in _NAMES:
        out += [q for q in p.rglob(n) if q.is_file()]
    out += [q for q in p.rglob("Powerlog_*.PLSQL*") if q.is_file()]
    return sorted(set(out))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_powerlog",
        description="Parse CurrentPowerlog.PLSQL (the macOS PowerLog). "
                    "Normalises the high-value PL*Agent* tables into one "
                    "event timeline: app usage / foreground, process start "
                    "/ stop, camera / microphone in use, location fixes "
                    "(lat/lon), battery level and power state, and "
                    "notification delivery. Timestamps auto-detected (Unix "
                    "or Mac-absolute) and converted to UTC. --list-tables "
                    "and --table dump any raw table. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_powerlog CurrentPowerlog.PLSQL --csv pl.csv\n"
                "  macos_powerlog /Volumes/Macintosh\\ HD --kind camera\n"
                "  macos_powerlog CurrentPowerlog.PLSQL --list-tables\n"
                "  macos_powerlog CurrentPowerlog.PLSQL --table "
                "PLLocationAgent_EventForward_TimerFire --json loc.json\n"))
    p.add_argument("path", type=Path,
                   help="a .PLSQL / .PLSQL.gz file or a mounted macOS volume")
    p.add_argument("--version", action="version",
                   version=f"macos_powerlog {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--list-tables", action="store_true")
    p.add_argument("--table", help="dump this raw table")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--kind", help="only this normalised kind (app usage / "
                   "process / camera / microphone / location / battery / ...)")
    p.add_argument("--grep", metavar="REGEX", help="match value / detail")
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
        from macos_powerlog.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_powerlog", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no PowerLog database found", file=sys.stderr)
        return 2

    if a.list_tables:
        for db in dbs:
            ctx.add_input(str(db))
            print(f"# {db}")
            for t in list_tables(str(db)):
                print(f"  {t}")
        ctx.finish(outputs=[])
        return 0

    if a.table:
        db = dbs[0]
        ctx.add_input(str(db))
        try:
            rows = dump_table(str(db), a.table, a.limit)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        cols = list(rows[0].keys()) if rows else []
        srows = [{k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                  for k, v in r.items()} for r in rows]
        if a.csv:
            tracelib.write_csv(srows, a.csv, cols, ctx,
                               confidence="medium", tz="mixed")
        if a.json:
            tracelib.write_json(srows, a.json, ctx,
                                confidence="medium", tz="mixed")
        if not a.quiet and not (a.csv or a.json):
            print(_json.dumps(srows, indent=2, default=str))
        ctx.finish(outputs=[a.csv, a.json])
        print(f"macos_powerlog: {a.table} -> {len(rows)} row(s)",
              file=sys.stderr)
        return 0 if rows else 1

    events = []
    matched = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            res = collect(str(db))
        except Exception as e:                    # noqa: BLE001
            ctx.error("powerlog-error", f"{db}: {e}")
            continue
        events += res.events
        matched += res.matched_tables
        for e in res.errors:
            ctx.error("table-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for e in events:
        r = e.row()
        r["severity"] = _flags.severity(e.notable)
        if a.kind and r["kind"] != a.kind:
            continue
        if a.since and (not r["timestamp"] or r["timestamp"][:10] < a.since):
            continue
        if a.until and (not r["timestamp"] or r["timestamp"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['value']} {r['detail']}"):
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
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            loc = f"  @{r['latitude']},{r['longitude']}" \
                if r["latitude"] else ""
            print(f"{r['timestamp'] or '(no time)':<21} {r['kind']:<14} "
                  f"{r['value']} {r['detail']}{loc}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_powerlog: {len(events)} event(s) from "
          f"{len(set(matched))} table(s) -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
