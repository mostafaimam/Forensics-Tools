from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_webcache import __version__, tracelib
from windows_webcache.analyze import analyze
from windows_webcache.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_webcache",
        description="Parse WebCacheV01.dat (the WinINET store used by IE, "
                    "legacy Edge and every WinINET app) into normalised "
                    "rows: history, cookies, cached content, downloads and "
                    "DOM storage with their URL, local filename, size, "
                    "access count and the modified / accessed / expiry / "
                    "sync FILETIMEs. History and cookie URLs are un-prefixed. "
                    "Flags executable / script fetches, IP-literal / punycode "
                    "hosts, file:// URLs and paste / tunnel sites. Vendors "
                    "the ESE reader; read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_webcache WebCacheV01.dat --csv webcache.csv\n"
                "  windows_webcache WebCacheV01.dat --type download --json "
                "dl.json\n"
                "  windows_webcache WebCacheV01.dat --grep 'pastebin|\\.exe'\n"
                "  windows_webcache WebCacheV01.dat --notable-only "
                "--min-severity high\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="WebCacheV01.dat file(s)")
    p.add_argument("--version", action="version",
                   version=f"windows_webcache {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", dest="entry_type",
                   help="history / cookie / content / download / dom / other")
    p.add_argument("--container", help="substring match on the container name")
    p.add_argument("--grep", metavar="REGEX", help="match the URL / filename")
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
        from windows_webcache.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_webcache", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in strpaths:
        ctx.add_input(p)

    res = analyze(strpaths)
    for e in res.errors:
        ctx.error("webcache-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for e in res.entries:
        r = row(e)
        if a.entry_type and r["entry_type"] != a.entry_type:
            continue
        if a.container and a.container.lower() not in r["container"].lower():
            continue
        if a.since and not (r["accessed"] or r["modified"] or "")[:10] >= \
                a.since:
            continue
        if a.until and (r["accessed"] or r["modified"] or "9999")[:10] > \
                a.until:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['url']} {r['filename']}"):
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

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_webcache: {len(res.entries)} entr(y/ies) "
          f"[{', '.join(f'{k}:{v}' for k, v in sorted(res.containers.items()))}]"
          f" -> {len(rows)} shown, {fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
