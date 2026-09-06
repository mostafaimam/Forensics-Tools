from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from trace_timeline import __version__
from trace_timeline.adapters import AdapterConfig, iter_events
from trace_timeline.htmlview import write_html
from trace_timeline.output import (
    render_table,
    write_bodyfile,
    write_csv,
    write_jsonl,
)
from trace_timeline.timeparse import TimeParseError, to_utc

_INPUT_SUFFIXES = {".csv", ".tsv", ".json", ".jsonl"}


def _expand_inputs(paths, recursive):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            for child in sorted(it):
                if child.is_file() and child.suffix.lower() in _INPUT_SUFFIXES:
                    yield child
        else:
            yield p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trace-timeline",
        description="Merge the CSV / JSON output of the trace-* tools (and "
                    "generic CSV/JSON) into one sorted, filterable UTC "
                    "super-timeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  trace-timeline case/ --csv timeline.csv\n"
            "  trace-timeline pf.csv recycle.csv --from 2024-03-01 "
            "--to 2024-03-08 --grep chrome\n"
            "  trace-timeline app.log.csv --time-field ts --message-field msg "
            "--jsonl out.jsonl\n"
        ),
    )
    p.add_argument("inputs", nargs="+", metavar="PATH",
                   help="CSV / JSON / JSONL files, or directories to search")
    p.add_argument("--version", action="version",
                   version=f"trace-timeline {__version__}")

    out = p.add_argument_group("output")
    out.add_argument("--csv", metavar="FILE", type=Path)
    out.add_argument("--jsonl", metavar="FILE", type=Path)
    out.add_argument("--html", metavar="FILE", type=Path,
                     help="self-contained HTML viewer (sort / filter / tag / export)")
    out.add_argument("--open", action="store_true",
                     help="open the --html file in a browser when done")
    out.add_argument("--bodyfile", metavar="FILE", type=Path,
                     help="TSK 3.x bodyfile (for mactime)")
    out.add_argument("-q", "--quiet", action="store_true")
    out.add_argument("--max-table", type=int, default=200,
                     help="rows to print to the console (default 200)")

    flt = p.add_argument_group("filters")
    flt.add_argument("--from", dest="dt_from", metavar="WHEN")
    flt.add_argument("--to", dest="dt_to", metavar="WHEN")
    flt.add_argument("--grep", metavar="REGEX",
                     help="keep rows whose description / extra match (case-insensitive)")
    flt.add_argument("--type", type=lambda s: s.split(","), default=None,
                     metavar="T,T", help="keep only these timestamp types")
    flt.add_argument("--tool", type=lambda s: s.split(","), default=None,
                     metavar="T,T", help="keep only these source tools")
    flt.add_argument("--host", metavar="NAME", help="keep only this host")
    flt.add_argument("--dedupe", action="store_true",
                     help="collapse identical (time, type, tool, description) rows")

    gen = p.add_argument_group("generic input")
    gen.add_argument("--time-field", action="append", default=[], metavar="COL")
    gen.add_argument("--message-field", action="append", default=[], metavar="COL")
    gen.add_argument("--epoch", action="store_true",
                     help="allow bare Unix epoch seconds / ms in time fields")
    gen.add_argument("--assume-host", metavar="NAME")
    gen.add_argument("--no-recurse", action="store_true")
    return p


def _run_gui(argv: list[str]) -> int:
    gp = argparse.ArgumentParser(prog="trace-timeline gui")
    gp.add_argument("inputs", nargs="*", metavar="PATH")
    gp.add_argument("--time-field", action="append", default=[])
    gp.add_argument("--message-field", action="append", default=[])
    gp.add_argument("--epoch", action="store_true")
    gp.add_argument("--assume-host")
    a = gp.parse_args(argv)
    from trace_timeline.gui import run
    return run(a.inputs, AdapterConfig(a.time_field, a.message_field,
                                       a.assume_host, a.epoch))


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "gui":
        return _run_gui(raw_argv[1:])

    args = build_parser().parse_args(argv)
    warnings: list[str] = []
    cfg = AdapterConfig(
        time_fields=args.time_field,
        message_fields=args.message_field,
        host=args.assume_host,
        allow_epoch=args.epoch,
    )

    dt_from = dt_to = None
    try:
        if args.dt_from:
            dt_from = to_utc(args.dt_from, allow_epoch=True)
        if args.dt_to:
            dt_to = to_utc(args.dt_to, allow_epoch=True)
    except TimeParseError as e:
        print(f"error: bad --from/--to value: {e}", file=sys.stderr)
        return 2

    grep = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    type_set = {t.strip() for t in args.type} if args.type else None
    tool_set = {t.strip() for t in args.tool} if args.tool else None

    events = []
    files = list(_expand_inputs(args.inputs, not args.no_recurse))
    if not files:
        print("error: no input files found", file=sys.stderr)
        return 2

    for f in files:
        if not f.exists():
            warnings.append(f"{f}: not found")
            continue
        try:
            for ev in iter_events(f, cfg, warnings):
                if dt_from and ev.timestamp < dt_from:
                    continue
                if dt_to and ev.timestamp > dt_to:
                    continue
                if type_set and ev.timestamp_type not in type_set:
                    continue
                if tool_set and ev.tool not in tool_set:
                    continue
                if args.host and ev.host != args.host:
                    continue
                if grep and not (grep.search(ev.description)
                                 or grep.search(str(ev.extra))):
                    continue
                events.append(ev)
        except OSError as e:
            warnings.append(f"{f}: {e}")

    events.sort(key=lambda e: (e.timestamp, e.timestamp_type, e.tool))

    if args.dedupe:
        seen = set()
        deduped = []
        for e in events:
            k = e.key()
            if k not in seen:
                seen.add(k)
                deduped.append(e)
        events = deduped

    wrote = []
    if args.csv:
        write_csv(events, args.csv); wrote.append(str(args.csv))
    if args.jsonl:
        write_jsonl(events, args.jsonl); wrote.append(str(args.jsonl))
    if args.bodyfile:
        write_bodyfile(events, args.bodyfile); wrote.append(str(args.bodyfile))
    if args.html:
        write_html(events, args.html, title=f"Timeline ({len(events)} events)")
        wrote.append(str(args.html))
        if args.open:
            import webbrowser
            webbrowser.open(args.html.resolve().as_uri())

    if not args.quiet:
        print(render_table(events, args.max_table))

    print(f"trace-timeline {__version__}: {len(events)} events from "
          f"{len(files)} file(s), {len(warnings)} warning(s)", file=sys.stderr)
    for w in warnings[:20]:
        print(f"  ! {w}", file=sys.stderr)
    for w in wrote:
        print(f"  wrote {w}", file=sys.stderr)

    return 0 if events or not warnings else 1


if __name__ == "__main__":
    raise SystemExit(main())
