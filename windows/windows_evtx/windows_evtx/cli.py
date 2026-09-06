from __future__ import annotations

import argparse
import sys
from pathlib import Path

from windows_evtx import __version__
from windows_evtx.evtx import EvtxError, FileHeader, iter_chunks, iter_records
from windows_evtx.evtx.headers import FILE_HEADER_SIZE
from windows_evtx.evtx.record import parse_record
from windows_evtx.output import (
    render_table,
    write_csv,
    write_json,
    write_jsonl,
    write_xml,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_evtx",
        description="Parse Windows event logs (.evtx) - binary + BinXml - into "
                    "standardised CSV, JSON/JSONL or XML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_evtx Security.evtx --csv security.csv\n"
            "  windows_evtx System.evtx --event-id 7045 --json services.json\n"
            "  windows_evtx *.evtx --from 2024-03-01 --to 2024-03-08 --csv week.csv\n"
        ),
    )
    p.add_argument("inputs", nargs="*", metavar="EVTX",
                   help=".evtx file(s) or directories to search")
    p.add_argument("--version", action="version",
                   version=f"windows_evtx {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")

    out = p.add_argument_group("output")
    out.add_argument("--csv", type=Path)
    out.add_argument("--json", type=Path)
    out.add_argument("--jsonl", type=Path)
    out.add_argument("--xml", type=Path)
    out.add_argument("-q", "--quiet", action="store_true")
    out.add_argument("--max-table", type=int, default=200)

    flt = p.add_argument_group("filters")
    flt.add_argument("--event-id", type=lambda s: set(s.split(",")), default=None,
                     metavar="ID,ID")
    flt.add_argument("--provider", type=lambda s: [x.lower() for x in s.split(",")],
                     default=None, metavar="NAME,NAME")
    flt.add_argument("--channel", type=lambda s: [x.lower() for x in s.split(",")],
                     default=None)
    flt.add_argument("--level", type=lambda s: [x.lower() for x in s.split(",")],
                     default=None, metavar="Error,Warning")
    flt.add_argument("--from", dest="dt_from", metavar="WHEN")
    flt.add_argument("--to", dest="dt_to", metavar="WHEN")
    flt.add_argument("--errors-only", action="store_true",
                     help="only records that failed to parse")
    return p


def _expand(inputs):
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*.evtx") if x.is_file())
        else:
            yield p


def _iso(s: str) -> str:
    return s.replace("Z", "").replace("T", " ")[:19]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from windows_evtx.gui import run_gui
        return run_gui([str(x) for x in (args.inputs or [])])
    files = list(_expand(args.inputs))
    if not files:
        print("error: no .evtx files found", file=sys.stderr)
        return 2

    dt_from = _iso(args.dt_from) if args.dt_from else None
    dt_to = _iso(args.dt_to) if args.dt_to else None
    lvl = set(args.level) if args.level else None

    records = []
    errors = 0
    scanned = 0
    opened = 0
    for f in files:
        try:
            data = f.read_bytes()
            FileHeader.parse(data)
            opened += 1
        except (OSError, EvtxError) as e:
            print(f"! {f}: {e}", file=sys.stderr)
            continue
        for number, chunk in iter_chunks(data):
            base = FILE_HEADER_SIZE + number * len(chunk)
            for raw in iter_records(number, chunk, base):
                scanned += 1
                rec = parse_record(raw, chunk)
                if rec.parse_error:
                    errors += 1
                if args.errors_only and not rec.parse_error:
                    continue
                if args.event_id and rec.event_id not in args.event_id:
                    continue
                if args.provider and rec.provider.lower() not in args.provider:
                    continue
                if args.channel and rec.channel.lower() not in args.channel:
                    continue
                if lvl and rec.level.lower() not in lvl:
                    continue
                tc = _iso(rec.time_created_utc or rec.timestamp_utc)
                if dt_from and tc and tc < dt_from:
                    continue
                if dt_to and tc and tc > dt_to:
                    continue
                rec._source = str(f)  # type: ignore[attr-defined]
                records.append(rec)

    records.sort(key=lambda r: (r.time_created_utc or r.timestamp_utc,
                                r.record_id))

    src = files[0].name if len(files) == 1 else f"{len(files)} files"
    if args.csv:
        write_csv(records, args.csv, src)
    if args.json:
        write_json(records, args.json, src)
    if args.jsonl:
        write_jsonl(records, args.jsonl, src)
    if args.xml:
        write_xml(records, args.xml)
    if not args.quiet and not any((args.csv, args.json, args.jsonl, args.xml)):
        print(render_table(records, args.max_table))

    print(f"windows_evtx {__version__}: {len(records)} record(s) "
          f"(of {scanned} scanned, {errors} parse error(s)) from {len(files)} file(s)",
          file=sys.stderr)
    for o in (args.csv, args.json, args.jsonl, args.xml):
        if o:
            print(f"  wrote {o}", file=sys.stderr)
    if opened == 0:
        return 2
    return 1 if errors and not records else 0


if __name__ == "__main__":
    raise SystemExit(main())
