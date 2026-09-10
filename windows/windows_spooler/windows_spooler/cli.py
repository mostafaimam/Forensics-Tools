from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_spooler import __version__, flags, tracelib
from windows_spooler.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["submit_time", "job_id", "user", "machine", "document", "printer",
           "driver", "datatype", "processor", "priority", "total_bytes",
           "spl_format", "spl_pages", "spl_bytes", "spl_detail",
           "spool_file", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_spooler",
        description="Print-spool artefact forensics. Pairs .shd job headers "
                    "with their .spl spool data and reports one row per job: "
                    "owner, source machine, document name, printer, driver, "
                    "submit time (from the SHD offset table + SYSTEMTIME), "
                    "and the .spl payload format (EMF, XPS/OpenXPS, "
                    "PostScript, PCL, PDF, raw) with a page count. "
                    "--extract copies the spool payloads out. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_spooler C:/Windows/System32/spool/PRINTERS --csv "
                "spool.csv\n"
                "  windows_spooler FP00004.shd FP00004.spl --json job.json\n"
                "  windows_spooler E:\\ --notable-only\n"
                "  windows_spooler PRINTERS --extract ./out\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help=".shd / .spl file(s), the PRINTERS folder, or a "
                        "mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_spooler {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--grep", metavar="REGEX",
                   help="match document / user / machine / printer")
    p.add_argument("--format", metavar="FMT",
                   help="only jobs whose .spl format matches (EMF, XPS, ...)")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="copy each .spl payload into DIR")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_spooler.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_spooler", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths, extract_dir=a.extract)
    for s in res.sources:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("spooler-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.format and a.format.lower() not in \
                (r.get("spl_format", "") or "").lower():
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "document", "user", "machine", "printer"))):
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
            print(f"{r.get('submit_time') or '(no time)':<21} "
                  f"job {r.get('job_id', 0):<6} "
                  f"{r.get('user') or '?'}@{r.get('machine') or '?'}{mark}")
            print(f"    doc: {r.get('document') or '(unknown)'}  ->  "
                  f"{r.get('printer') or '?'}")
            print(f"    spl: {r.get('spl_format')} "
                  f"{r.get('spl_pages') or 0}p {r.get('spl_bytes') or 0}B "
                  f"{r.get('spl_detail') or ''}")
            for nn in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_spooler: {res.shd_files} .shd, {res.spl_files} .spl -> "
          f"{len(rows)} job(s), {fl} flagged (worst: {flags.worst(rows)})",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
