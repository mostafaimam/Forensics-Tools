from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_bits import __version__, flags, tracelib
from windows_bits.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["ctime", "mtime", "job_name", "job_id", "type", "state", "owner",
           "url", "dest", "tmp_file", "download_size", "bytes_transferred",
           "offset", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_bits",
        description="BITS transfer-history forensics. Carves download / "
                    "upload jobs out of the legacy qmgr0.dat / qmgr1.dat "
                    "queue files and the modern ESE qmgr.db: remote URL, "
                    "local destination, scratch file, owner SID, job type / "
                    "state, byte counts and create / modify times. Flags "
                    "raw-IP URLs, executable payloads, system-directory "
                    "destinations, upload jobs and updater-mimic job names. "
                    "Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_bits qmgr.db --csv bits.csv\n"
                "  windows_bits C:/ProgramData/Microsoft/Network/Downloader "
                "--notable-only\n"
                "  windows_bits E:\\ --min-severity high --json bits.json\n"
                "  windows_bits qmgr0.dat --grep '\\.exe$'\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="qmgr*.dat / qmgr.db file(s), the Downloader folder, "
                        "or a mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_bits {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", choices=["download", "upload", "upload-reply"])
    p.add_argument("--grep", metavar="REGEX",
                   help="match url / dest / job name / owner")
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
        from windows_bits.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_bits", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths)
    for s in res.sources:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("bits-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.type and r.get("type") != a.type:
            continue
        t = r.get("ctime") or r.get("mtime") or ""
        if a.since and (not t or t[:10] < a.since):
            continue
        if a.until and (not t or t[:10] > a.until):
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "url", "dest", "job_name", "owner"))):
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
            mark = f"  [{r['severity']}]" if r.get("severity", "none") != \
                "none" else ""
            print(f"{r.get('ctime') or r.get('mtime') or '(no time)':<21} "
                  f"{r.get('type', '?'):<8} {r.get('state', ''):<12} "
                  f"{r.get('job_name', '')[:24]}{mark}")
            print(f"    {r.get('url', '')}")
            print(f"    -> {r.get('dest', '') or r.get('tmp_file', '')}")
            for n in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_bits: {res.files_seen} qmgr file(s), ~{res.jobs} job(s) "
          f"-> {len(rows)} transfer(s), {fl} flagged "
          f"(worst: {flags.worst(rows)})", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
