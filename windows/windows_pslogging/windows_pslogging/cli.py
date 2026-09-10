from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_pslogging import __version__, tracelib
from windows_pslogging import flags as _flags
from windows_pslogging.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["time", "kind", "event_id", "computer", "user", "host_app",
           "path", "scriptblock_id", "fragments", "decoded", "text",
           "severity", "source", "notable"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_pslogging",
        description="PowerShell forensics. Reassembles ScriptBlock logging "
                    "(4104) across its multi-part records, pulls Module "
                    "logging (4103) and the classic 400 / 500 / 600 events, "
                    "and parses PowerShell_transcript.* files. Decodes "
                    "-EncodedCommand / FromBase64String / gzip+base64 "
                    "payloads in place. One row per reassembled script: "
                    "time (UTC), computer, user, host application, the "
                    "decoded text, and the flags raised (download cradle, "
                    "AMSI bypass, reflective load, reverse shell, credential "
                    "access, obfuscation). Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_pslogging 'Microsoft-Windows-PowerShell%4"
                "Operational.evtx' --csv ps.csv\n"
                "  windows_pslogging E:\\ --notable-only --min-severity high\n"
                "  windows_pslogging transcript.txt --json t.json\n"
                "  windows_pslogging /mnt/evtx --grep 'DownloadString'\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="EVTX file(s), transcript(s), or a directory / root")
    p.add_argument("--version", action="version",
                   version=f"windows_pslogging {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", choices=["scriptblock", "module", "classic",
                                      "transcript"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match the decoded script text / host / user")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--full-text", action="store_true",
                   help="print the whole decoded script in the text report")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_pslogging.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_pslogging", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths)
    for s in {sc.source for sc in res.scripts}:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("pslogging-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for sc in res.scripts:
        r = sc.row()
        r["severity"] = _flags.severity(sc.notable)
        if a.kind and r["kind"] != a.kind:
            continue
        if a.since and (not r["time"] or r["time"][:10] < a.since):
            continue
        if a.until and (not r["time"] or r["time"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["text"], r["host_app"], r["user"]))):
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
            print(f"{r['time'] or '(no time)':<21} {r['kind']:<11} "
                  f"{r['computer']}/{r['user']}  {r['host_app']}{mark}")
            if r["decoded"]:
                print(f"    decoded: {r['decoded']}")
            snippet = r["text"] if a.full_text else \
                re.sub(r"\s+", " ", r["text"])[:200]
            print(f"    {snippet}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_pslogging: {res.events_4104} x 4104 -> "
          f"{sum(1 for s in res.scripts if s.kind == 'scriptblock')} "
          f"script(s), {res.events_4103} x 4103, {res.transcripts} "
          f"transcript(s) -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
