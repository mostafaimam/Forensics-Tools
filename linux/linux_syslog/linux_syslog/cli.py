from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from linux_syslog import __version__
from linux_syslog.collect import discover, iter_records, parse_tz
from linux_syslog.events import extract
from linux_syslog.output import (
    EVENT_COLUMNS,
    RECORD_COLUMNS,
    event_row,
    record_row,
    render_table,
    write_csv,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_syslog",
        description="Normalise classic Linux text logs (syslog / messages / "
                    "auth.log / secure, incl. rotated and .gz) into a record "
                    "timeline or a stream of structured security events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  linux_syslog /var/log/auth.log --events\n"
            "  linux_syslog /mnt/img --root --events --csv events.csv\n"
            "  linux_syslog /var/log/syslog* --severity err,crit,alert\n"
            "  linux_syslog /var/log/auth.log --events --category ssh "
            "--result failure\n"
        ),
    )
    p.add_argument("inputs", nargs="+", type=Path, metavar="PATH",
                   help="log files, or a filesystem root with --root")
    p.add_argument("--version", action="version",
                   version=f"linux_syslog {__version__}")
    p.add_argument("--root", action="store_true",
                   help="treat the argument as a filesystem root; scan "
                        "var/log for known log families")
    p.add_argument("--events", action="store_true",
                   help="emit structured security events instead of records")
    p.add_argument("--tz", metavar="+HH:MM",
                   help="timezone of naive (BSD-format) timestamps "
                        "(default: UTC); ISO/RFC5424 offsets are always honoured")
    p.add_argument("--year", type=int,
                   help="override the year for BSD timestamps that carry none")
    # record filters
    p.add_argument("--tag", type=_csv, help="keep only these syslog tags")
    p.add_argument("--host", type=_csv, help="keep only these hosts")
    p.add_argument("--severity", type=_csv,
                   help="keep only these severities (emerg..debug)")
    p.add_argument("--facility", type=_csv, help="keep only these facilities")
    p.add_argument("--grep", metavar="REGEX",
                   help="keep only messages matching this regex (case-insensitive)")
    # event filters
    p.add_argument("--category", type=_csv,
                   help="events: keep only these categories "
                        "(ssh, sudo, su, session, cron, account, pam)")
    p.add_argument("--result", type=_csv,
                   help="events: keep only these results (success, failure)")
    p.add_argument("--user", type=_csv, help="events: keep only these users")
    p.add_argument("--ip", type=_csv, help="events: keep only these source IPs")
    p.add_argument("--from", dest="dt_from")
    p.add_argument("--to", dest="dt_to")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _csv(s: str):
    return {x.strip() for x in s.split(",") if x.strip()}


def _key(s: str) -> str:
    return s.replace("Z", "").replace("T", " ")[:19]


def _files(args) -> list[Path]:
    if args.root:
        roots = args.inputs
        out: list[Path] = []
        for r in roots:
            if not r.exists():
                print(f"! not found: {r}", file=sys.stderr)
                continue
            out += discover(r)
        return out
    return list(args.inputs)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        tz = parse_tz(args.tz)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    grep = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    dt_from = _key(args.dt_from) if args.dt_from else None
    dt_to = _key(args.dt_to) if args.dt_to else None

    files = _files(args)
    if not files:
        print("no log files to read", file=sys.stderr)
        return 2
    if not any(f.exists() for f in files):
        for f in files:
            print(f"! not found: {f}", file=sys.stderr)
        return 2

    records = []
    parsed = unparsed = 0
    for f in files:
        if not f.exists():
            print(f"! not found: {f}", file=sys.stderr)
            continue
        for rec in iter_records(f, tz, year=args.year):
            if rec.timestamp is None:
                unparsed += 1
            else:
                parsed += 1
            records.append(rec)

    records.sort(key=lambda r: (r.timestamp or _MIN, r.source_file, r.line_no))

    if args.events:
        rows = []
        for rec in records:
            ev = extract(rec)
            if ev is None:
                continue
            if args.category and ev.category not in args.category:
                continue
            if args.result and (ev.result or "") not in args.result:
                continue
            if args.user and ev.user not in args.user \
                    and ev.target_user not in args.user:
                continue
            if args.ip and ev.source_ip not in args.ip:
                continue
            if not _in_window(ev.timestamp, dt_from, dt_to):
                continue
            rows.append(event_row(ev))
        _emit(rows, EVENT_COLUMNS, args)
        fails = sum(1 for r in rows if r["result"] == "failure")
        print(f"linux_syslog {__version__}: {len(rows)} event(s) "
              f"({fails} failure(s)) from {len(files)} file(s)", file=sys.stderr)
        return 0 if rows else 1

    rows = []
    for rec in records:
        if args.tag and rec.tag not in args.tag:
            continue
        if args.host and rec.host not in args.host:
            continue
        if args.severity and rec.severity not in args.severity:
            continue
        if args.facility and rec.facility not in args.facility:
            continue
        if grep and not grep.search(rec.message):
            continue
        if not _in_window(rec.timestamp, dt_from, dt_to):
            continue
        rows.append(record_row(rec))
    _emit(rows, RECORD_COLUMNS, args)
    print(f"linux_syslog {__version__}: {len(rows)} record(s) shown; "
          f"{parsed} parsed, {unparsed} without a timestamp, "
          f"{len(files)} file(s)", file=sys.stderr)
    return 0 if rows else 1


_MIN = datetime(1, 1, 1, tzinfo=timezone.utc)


def _in_window(ts, dt_from, dt_to) -> bool:
    if ts is None:
        return not (dt_from or dt_to)
    iso = ts.strftime("%Y-%m-%d %H:%M:%S")
    if dt_from and iso < dt_from:
        return False
    if dt_to and iso > dt_to:
        return False
    return True


def _emit(rows, columns, args) -> None:
    if args.csv:
        write_csv(rows, columns, args.csv)
    if args.json:
        write_json(rows, args.json)
    if not args.quiet and not (args.csv or args.json):
        print(render_table(rows, columns))


if __name__ == "__main__":
    raise SystemExit(main())
