from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_logfile import __version__, flags, tracelib
from windows_logfile.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["lsn", "action", "name", "mft", "parent_mft", "namespace",
           "created", "modified", "real_size", "redo_op", "undo_op",
           "transaction_id", "page", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_logfile",
        description="NTFS $LogFile transaction-log forensics. Reads the RSTR "
                    "/ RCRD pages (fixing the update-sequence array), walks "
                    "the log-record stream, decodes the redo / undo "
                    "operations and pulls the FILE_NAME attribute out of the "
                    "index-entry operations to reconstruct high-level "
                    "events: file created / deleted / renamed, MFT record "
                    "initialised / freed, resident value updated. Flags "
                    "create+delete twins, timestomping, executable "
                    "deletions and ADS names. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_logfile $LogFile --csv logfile.csv\n"
                "  windows_logfile ./LogFile.bin --action 'file deleted'\n"
                "  windows_logfile E:\\ --notable-only --min-severity high\n"
                "  windows_logfile $LogFile --grep '\\.exe$'\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="$LogFile (extracted) file(s), a folder, or a mount "
                        "root")
    p.add_argument("--version", action="version",
                   version=f"windows_logfile {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--action", metavar="SUBSTR",
                   help="match the reconstructed action text")
    p.add_argument("--grep", metavar="REGEX", help="match the file name")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--named-only", action="store_true",
                   help="only events that carry a recovered file name")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_logfile.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_logfile", __version__)
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
        ctx.error("logfile-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        if a.action and a.action.lower() not in r["action"].lower():
            continue
        if a.named_only and not r.get("name"):
            continue
        if a.notable_only and not r.get("notable"):
            continue
        if a.min_severity and _SEV[r.get("severity", "none")] < \
                _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r.get("name", "")):
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
            print(f"LSN {r['lsn']:<16} {r['action']:<38} "
                  f"{r.get('name') or ''}{mark}")
            if r.get("created") or r.get("modified"):
                print(f"    C={r.get('created') or '-'}  "
                      f"M={r.get('modified') or '-'}  "
                      f"size={r.get('real_size') or 0}  "
                      f"parent MFT={r.get('parent_mft') or '?'}")
            for nn in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_logfile: {res.files} file(s), {res.rcrd_pages} RCRD + "
          f"{res.rstr_pages} RSTR pages, {res.records} log record(s) -> "
          f"{len(rows)} event(s), {fl} flagged (worst: {flags.worst(rows)})",
          file=sys.stderr)
    for e in res.errors[:10]:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
