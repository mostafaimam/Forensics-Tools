from __future__ import annotations

import argparse
import gzip
import sys
from pathlib import Path

from linux_utmp import __version__
from linux_utmp.lastlog import looks_like_lastlog
from linux_utmp.lastlog import parse as parse_lastlog
from linux_utmp.output import (
    LASTLOG_COLUMNS,
    RECORD_COLUMNS,
    SESSION_COLUMNS,
    lastlog_row,
    record_row,
    render_table,
    session_row,
    write_csv,
    write_json,
)
from linux_utmp.sessions import build_sessions
from linux_utmp.utmp import looks_like_utmp
from linux_utmp.utmp import parse as parse_utmp


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    return data


def _kind(name: str, data: bytes, forced: str | None) -> str:
    if forced:
        return forced
    low = name.lower()
    if "lastlog" in low:
        return "lastlog"
    if "btmp" in low:
        return "btmp"
    if "wtmp" in low:
        return "wtmp"
    if "utmp" in low:
        return "utmp"
    if looks_like_utmp(data):
        return "wtmp"
    if looks_like_lastlog(data):
        return "lastlog"
    return "wtmp"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_utmp",
        description="Parse Linux login records: wtmp / btmp / utmp and lastlog. "
                    "Emits a record timeline and (for wtmp) paired login/logout "
                    "sessions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  linux_utmp /var/log/wtmp --sessions --csv sessions.csv\n"
            "  linux_utmp /var/log/btmp --csv failed_logins.csv\n"
            "  linux_utmp /var/log/wtmp.1.gz /var/log/wtmp --csv all.csv\n"
            "  linux_utmp /var/log/lastlog --csv lastlog.csv\n"
        ),
    )
    p.add_argument("inputs", nargs="*", type=Path, metavar="FILE")
    p.add_argument("--version", action="version",
                   version=f"linux_utmp {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--as", dest="forced", choices=["wtmp", "btmp", "utmp", "lastlog"],
                   help="force the record type instead of guessing")
    p.add_argument("--big-endian", action="store_true",
                   help="records are big-endian (rare - e.g. s390x, ppc64)")
    p.add_argument("--sessions", action="store_true",
                   help="output paired login/logout sessions (wtmp)")
    p.add_argument("--user", help="keep only this user")
    p.add_argument("--type", type=lambda s: {x.strip().upper() for x in s.split(",")},
                   default=None, metavar="T,T",
                   help="keep only these record types (USER_PROCESS, BOOT_TIME, ...)")
    p.add_argument("--from", dest="dt_from")
    p.add_argument("--to", dest="dt_to")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _iso_key(s: str) -> str:
    return s.replace("Z", "").replace("T", " ")[:19]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from linux_utmp.gui import run_gui
        return run_gui([str(x) for x in (args.inputs or [])])
    dt_from = _iso_key(args.dt_from) if args.dt_from else None
    dt_to = _iso_key(args.dt_to) if args.dt_to else None

    records = []          # (UtmpRecord, source)
    lastlog_rows = []
    kinds = set()
    for path in args.inputs:
        if not path.exists():
            print(f"! not found: {path}", file=sys.stderr)
            continue
        data = _read(path)
        kind = _kind(path.name, data, args.forced)
        kinds.add(kind)
        if kind == "lastlog":
            for e in parse_lastlog(data, args.big_endian):
                lastlog_rows.append(lastlog_row(e, str(path)))
        else:
            for r in parse_utmp(data, args.big_endian):
                records.append((r, str(path)))

    if lastlog_rows and not records:
        lastlog_rows.sort(key=lambda r: r["last_login_utc"])
        _emit(lastlog_rows, LASTLOG_COLUMNS, args)
        print(f"linux_utmp {__version__}: {len(lastlog_rows)} lastlog entr(y|ies)",
              file=sys.stderr)
        return 0

    recs = [r for r, _s in records]
    if args.sessions:
        sess = build_sessions(recs)
        by_login = {r.index: src for r, src in records}
        rows = [session_row(s, by_login.get(s.login_index, "")) for s in sess]
        rows = _filter_sessions(rows, args, dt_from, dt_to)
        _emit(rows, SESSION_COLUMNS, args)
        opn = sum(1 for r in rows if r["still_open"] == "yes")
        print(f"linux_utmp {__version__}: {len(rows)} session(s), {opn} still open",
              file=sys.stderr)
        return 0

    rows = []
    for r, src in records:
        if args.user and r.user != args.user:
            continue
        if args.type and r.type_name not in args.type:
            continue
        row = record_row(r, src)
        if dt_from and row["timestamp_utc"] and _iso_key(row["timestamp_utc"]) < dt_from:
            continue
        if dt_to and row["timestamp_utc"] and _iso_key(row["timestamp_utc"]) > dt_to:
            continue
        rows.append(row)
    rows.sort(key=lambda r: r["timestamp_utc"])
    _emit(rows, RECORD_COLUMNS, args)
    print(f"linux_utmp {__version__}: {len(rows)} record(s) "
          f"({'/'.join(sorted(kinds))})", file=sys.stderr)
    return 0 if rows or lastlog_rows else 1


def _filter_sessions(rows, args, dt_from, dt_to):
    out = []
    for r in rows:
        if args.user and r["user"] != args.user:
            continue
        if dt_from and r["login_utc"] and _iso_key(r["login_utc"]) < dt_from:
            continue
        if dt_to and r["login_utc"] and _iso_key(r["login_utc"]) > dt_to:
            continue
        out.append(r)
    return out


def _emit(rows, columns, args) -> None:
    if args.csv:
        write_csv(rows, columns, args.csv)
    if args.json:
        write_json(rows, args.json)
    if not args.quiet and not (args.csv or args.json):
        print(render_table(rows, columns))


if __name__ == "__main__":
    raise SystemExit(main())
