from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from network_http import __version__, tracelib
from network_http.carve import analyze, extract
from network_http.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_http",
        description="Carve HTTP transfers out of a pcap / pcapng: reassemble "
                    "TCP, parse the HTTP/1.x messages (chunked + gzip), pair "
                    "requests with responses, hash every transferred body and "
                    "optionally write it to disk. Uploaded bodies are carved "
                    "too. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  network_http capture.pcap\n"
            "  network_http traffic.pcapng --extract ./objects --csv man.csv\n"
            "  network_http *.pcap --notable-only --min-severity high\n"
            "  network_http c.pcap --grep '\\.exe|\\.ps1' --uploads\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"network_http {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="write every carved body into this directory")
    p.add_argument("--downloads", action="store_true",
                   help="only response bodies")
    p.add_argument("--uploads", action="store_true",
                   help="only request bodies")
    p.add_argument("--min-size", type=int, default=1, metavar="BYTES")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match URL / filename / content-type (case-insensitive)")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from network_http.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a pcap / pcapng file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    prog = None
    if not a.quiet:
        def prog(n):  # noqa: E306
            sys.stderr.write(f"\r  {n} packets")
            sys.stderr.flush()

    ctx = tracelib.context(a, "network_http", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in a.paths:
        ctx.add_input(str(p))

    res = analyze([str(p) for p in a.paths], min_size=a.min_size,
                  keep_bodies=bool(a.extract), progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    if a.extract:
        wrote = extract(res, str(a.extract))
        if not a.quiet:
            print(f"  extracted {wrote} file(s) -> {a.extract}",
                  file=sys.stderr)

    rows = []
    for o in res.objects:
        if a.downloads and o.direction != "download":
            continue
        if a.uploads and o.direction != "upload":
            continue
        r = row(o)
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                r["url"] + " " + r["filename"] + " " + r["content_type"]):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    for _e in res.errors:
        ctx.error("source-error", _e)
    _mpath = ctx.finish(outputs=[a.csv, a.json])
    dl = sum(1 for r in rows if r["direction"] == "download")
    up = len(rows) - dl
    fl = sum(1 for r in rows if r["notable"])
    print(f"network_http: {res.packets} packets, {res.connections} TCP conns, "
          f"{res.transactions} HTTP transactions -> {len(rows)} object(s) "
          f"({dl} download, {up} upload), {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
