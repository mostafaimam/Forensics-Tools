from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from linux_journal import __version__, tracelib
from linux_journal.collect import collect
from linux_journal.output import COLUMNS, record, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
_PRIO_NUM = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4,
             "notice": 5, "info": 6, "debug": 7}


def _parse_when(s: str) -> int:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(s, fmt)
                       .replace(tzinfo=timezone.utc).timestamp() * 1_000_000)
        except ValueError:
            continue
    raise SystemExit(f"bad date/time: {s!r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_journal",
        description="Read the systemd journal (.journal) binary format under a "
                    "mounted image or a live root: walk the object arena, "
                    "resolve each entry's data objects into FIELD=value pairs "
                    "and emit one record per entry with the realtime (UTC) and "
                    "monotonic timestamps, boot id and every field. Merges "
                    "several files into one ordered timeline. Filters on any "
                    "field, a priority threshold, a boot id and a time window. "
                    "Flags high-priority records, coredumps, download cradles, "
                    "recon tooling, SSH / sudo auth failures and audit events. "
                    "Pure standard library (XZ data objects only; LZ4 / ZSTD "
                    "need a non-stdlib codec).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_journal /mnt/evidence\n"
                "  linux_journal / --unit sshd.service --csv ssh.csv\n"
                "  linux_journal /mnt/img -p err --notable-only\n"
                "  linux_journal /mnt/img --field _UID=0 --grep sudo\n"
                "  linux_journal /mnt/img --boot <boot-id> --json j.json\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="filesystem root(s) to walk, or individual .journal "
                        "files")
    p.add_argument("--version", action="version",
                   version=f"linux_journal {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--unit", help="only this _SYSTEMD_UNIT (or UNIT)")
    p.add_argument("--field", action="append", metavar="NAME=VALUE",
                   help="require this field value (repeatable, AND)")
    p.add_argument("--boot", help="only this _BOOT_ID")
    p.add_argument("-p", "--priority",
                   choices=list(_PRIO_NUM), help="max priority (inclusive)")
    p.add_argument("--grep", metavar="REGEX", help="match MESSAGE / _COMM / "
                   "_CMDLINE / _EXE")
    p.add_argument("--since", metavar="WHEN")
    p.add_argument("--until", metavar="WHEN")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--list-boots", action="store_true",
                   help="print the boot ids and their time spans, then exit")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from linux_journal.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "linux_journal", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths)
    for f in res.files:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("journal-error", e)
    for w in res.warnings:
        ctx.partial(w)

    if a.list_boots:
        for bid, (lo, hi) in res.boots.items():
            print(f"{bid}  {lo}  ..  {hi}")
        ctx.finish(outputs=[])
        return 0 if res.boots else 1

    since = _parse_when(a.since) if a.since else None
    until = _parse_when(a.until) if a.until else None
    if until and a.until and len(a.until) == 10:
        until += 86_400_000_000 - 1
    fields = {}
    for kv in a.field or []:
        k, _, v = kv.partition("=")
        fields[k] = v
    grep = re.compile(a.grep, re.I) if a.grep else None
    pmax = _PRIO_NUM[a.priority] if a.priority else None

    rows, records, kept = [], [], []
    for e in res.entries:
        f = e.fields
        if a.unit and (f.get("_SYSTEMD_UNIT") != a.unit
                       and f.get("UNIT") != a.unit):
            continue
        if a.boot and e.boot_id != a.boot:
            continue
        if since and (e.realtime_us or 0) < since:
            continue
        if until and (e.realtime_us or 0) > until:
            continue
        if pmax is not None:
            try:
                if int(f.get("PRIORITY", "6")) > pmax:
                    continue
            except ValueError:
                continue
        if fields and any(f.get(k) != v for k, v in fields.items()):
            continue
        r = row(e)
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                f.get("MESSAGE", ""), f.get("_COMM", ""),
                f.get("_CMDLINE", ""), f.get("_EXE", "")))):
            continue
        rows.append(r)
        kept.append(e)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        records = [record(e) for e in kept]
        tracelib.write_json(records, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.boots, res.warnings), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"linux_journal: {len(res.entries)} entr(y/ies) from "
          f"{len(res.files)} file(s) -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    for w in res.warnings:
        print(f"  ! {w}", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
