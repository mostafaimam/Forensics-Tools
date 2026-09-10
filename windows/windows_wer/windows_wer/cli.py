from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_wer import __version__, flags, tracelib
from windows_wer.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["time", "event_type", "app_name", "app_path", "app_version",
           "mod_name", "mod_path", "exception_code", "exception_offset",
           "pid", "friendly", "report_id", "report_status", "consent",
           "os_version", "loaded_modules", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_wer",
        description="Windows Error Reporting forensics. Parses .wer report "
                    "files (and the ReportArchive / ReportQueue stores) into "
                    "one row per crash / hang: faulting application and full "
                    "path, version, faulting module, exception code / "
                    "offset, event time and the problem signature. A .wer "
                    "report is durable proof a program ran, often outliving "
                    "the executable. Flags faults in binaries / modules "
                    "under writable paths, LOLBin crashes and "
                    "exploit-shaped exceptions. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_wer C:/ProgramData/Microsoft/Windows/WER --csv "
                "wer.csv\n"
                "  windows_wer Report.wer --json r.json\n"
                "  windows_wer E:\\ --notable-only --min-severity high\n"
                "  windows_wer WER --grep 'powershell|\\\\Temp\\\\'\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help=".wer file(s), a WER store folder, or a mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_wer {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--event-type", metavar="TYPE",
                   help="exact EventType (APPCRASH, BEX, APPHANG, ...)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match app / module path / name / friendly name")
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
        from windows_wer.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_wer", __version__)
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
        ctx.error("wer-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.event_type and r.get("event_type") != a.event_type:
            continue
        t = r.get("time") or ""
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
                "app_name", "app_path", "mod_name", "mod_path", "friendly"))):
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
            mark = f"  [{r['severity']}]" if r.get("severity", "none") != \
                "none" else ""
            print(f"{r.get('time') or '(no time)':<21} "
                  f"{r.get('event_type', ''):<10} "
                  f"{r.get('app_name', '')}{mark}")
            if r.get("app_path"):
                print(f"    app: {r['app_path']} {r.get('app_version', '')}")
            if r.get("mod_name"):
                print(f"    mod: {r.get('mod_path') or r['mod_name']}  "
                      f"code {r.get('exception_code', '')} "
                      f"@ {r.get('exception_offset', '')}")
            for nn in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_wer: {res.reports} report(s) -> {len(rows)} shown, "
          f"{fl} flagged (worst: {flags.worst(rows)})", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
