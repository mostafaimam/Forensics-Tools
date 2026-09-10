from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_fsevents import __version__, tracelib
from macos_fsevents.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
_FSEV = {
    "a security / logging artefact was removed": "high",
    "a security / logging artefact was renamed": "high",
    "a security / logging artefact was touched": "medium",
    "file created in a user-writable / temp path": "low",
    "file removed from a user-writable / temp path": "low",
    "volume mount event": "low",
    "volume unmount event": "low",
}
COLUMNS = ["approx_time", "path", "flags", "flags_hex", "event_id", "node_id",
           "dls_version", "source_file", "severity", "notable"]


def _severity(notable) -> str:
    top = "none"
    for n in notable:
        for k, v in _FSEV.items():
            if n.startswith(k) and _SEV[v] > _SEV[top]:
                top = v
    return top


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_fsevents",
        description="Parse the /.fseventsd file-system change log (gzip "
                    "binary). Reads every log file, decodes the DLS1 / DLS2 "
                    "/ DLS3 pages into records of <path> <event-id> <flags> "
                    "[<node-id>], and decodes the change flags (Created / "
                    "Removed / Renamed / Modified / FolderCreated / "
                    "InodeMetaMod / XattrModified / ...). There is no "
                    "per-record timestamp; ordering is by event id and "
                    "approx_time is the source log file's mtime. Flags "
                    "deletion of security artefacts and create / remove in "
                    "temp paths. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_fsevents /Volumes/Macintosh\\ HD --csv fse.csv\n"
                "  macos_fsevents 0000000001a2b3c4 --json one.json\n"
                "  macos_fsevents /mnt/mac --grep '\\.fseventsd|TCC' "
                "--notable-only\n"
                "  macos_fsevents /mnt/mac --flag Removed --grep '/Users/'\n"))
    p.add_argument("path", type=Path,
                   help="a mounted macOS volume, a .fseventsd dir, or a log")
    p.add_argument("--version", action="version",
                   version=f"macos_fsevents {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--flag", action="append",
                   help="only records carrying this flag name (repeatable)")
    p.add_argument("--grep", metavar="REGEX", help="match the path")
    p.add_argument("--no-dedupe", action="store_true",
                   help="keep duplicate records across overlapping logs")
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
        from macos_fsevents.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_fsevents", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(str(a.path))

    res = collect(str(a.path), dedupe=not a.no_dedupe)
    for e in res.errors:
        ctx.error("fsevents-error", e)
    if res.files == 0:
        print("no .fseventsd logs found", file=sys.stderr)
        return 2

    want = {f.lower() for f in a.flag} if a.flag else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for rec in res.records:
        r = rec.row()
        r["severity"] = _severity(rec.notable)
        if want and not any(fn.lower() in want for fn in rec.flag_names):
            continue
        if grep and not grep.search(r["path"]):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="assumed-utc")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="assumed-utc")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['event_id']:>16}  {r['flags']:<40} {r['path']}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_fsevents: {res.files} log(s) -> {len(res.records)} "
          f"record(s) -> {len(rows)} shown, {fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
