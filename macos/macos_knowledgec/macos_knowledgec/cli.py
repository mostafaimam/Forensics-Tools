from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_knowledgec import __version__, tracelib
from macos_knowledgec import flags as _flags
from macos_knowledgec.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["start", "end", "duration_s", "stream", "stream_raw", "value",
           "title", "bundle_id", "device_id", "gmt_offset", "severity",
           "source", "notable"]


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    return [q for q in p.rglob("knowledgeC.db") if q.is_file()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_knowledgec",
        description="Parse knowledgeC.db (the CoreDuet activity store behind "
                    "Siri suggestions and Screen Time). Decodes the useful "
                    "ZOBJECT streams: /app/usage, /app/inFocus, /app/webUsage, "
                    "/safari/history, /display/isBacklit, /device/isLocked, "
                    "/app/intents, /app/mediaUsage, /notification/usage, "
                    "/app/install. Each row: stream, value (bundle id / "
                    "domain), start / end (Mac absolute time -> UTC), "
                    "duration, device id, recorded GMT offset, metadata "
                    "title. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_knowledgec knowledgeC.db --csv kc.csv\n"
                "  macos_knowledgec /Volumes/Macintosh\\ HD --stream "
                "/app/usage\n"
                "  macos_knowledgec knowledgeC.db --app Terminal --json t.json\n"
                "  macos_knowledgec knowledgeC.db --notable-only "
                "--min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a knowledgeC.db or a mounted macOS volume")
    p.add_argument("--version", action="version",
                   version=f"macos_knowledgec {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--stream", action="append",
                   help="only this ZSTREAMNAME (repeatable)")
    p.add_argument("--app", help="regex match on the value / bundle id / "
                   "title")
    p.add_argument("--min-duration", type=int, default=0)
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
        from macos_knowledgec.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_knowledgec", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no knowledgeC.db found", file=sys.stderr)
        return 2

    events = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            events += parse(str(db), a.stream)
        except Exception as e:                    # noqa: BLE001
            ctx.error("kc-error", f"{db}: {e}")

    app_rx = re.compile(a.app, re.I) if a.app else None
    rows = []
    for e in events:
        r = e.row()
        r["severity"] = _flags.severity(e.notable)
        if app_rx and not app_rx.search(f"{r['value']} {r['bundle_id']} "
                                        f"{r['title']}"):
            continue
        if a.min_duration and r["duration_s"] < a.min_duration:
            continue
        if a.since and (not r["start"] or r["start"][:10] < a.since):
            continue
        if a.until and (not r["start"] or r["start"][:10] > a.until):
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
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            d = f" {r['duration_s']}s" if r["duration_s"] else ""
            t = f"  ({r['title']})" if r["title"] else ""
            print(f"{r['start'] or '(no time)':<21} {r['stream']:<24} "
                  f"{r['value']}{d}{t}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_knowledgec: {len(events)} event(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
