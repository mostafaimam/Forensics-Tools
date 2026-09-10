from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_defender import __version__, flags, tracelib
from windows_defender.collect import collect

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["time", "kind", "threat", "path", "user", "process", "action",
           "event_id", "pid", "detail", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_defender",
        description="Microsoft Defender forensics. Builds one detection "
                    "timeline from MPLog support logs, the Windows Defender "
                    "Operational event log, the RC4-obfuscated Quarantine "
                    "store (threat name, original path, time) and the "
                    "SOFTWARE-hive exclusions and protection switches. "
                    "Read-only; the quarantine key is a fixed public "
                    "obfuscation key - nothing is cracked.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_defender 'C:/ProgramData/Microsoft/Windows "
                "Defender' --csv def.csv\n"
                "  windows_defender MPLog-20240101-120000.log --kind "
                "mplog-detection\n"
                "  windows_defender E:\\ --notable-only --min-severity high\n"
                "  windows_defender SOFTWARE --kind exclusion-paths\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="Defender folder, MPLog / EVTX / SOFTWARE file, "
                        "Quarantine dir, or a mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_defender {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--kind", help="exact match on the record kind "
                                  "(e.g. quarantine, evtx-detection, "
                                  "mplog-detection, exclusion-paths)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match threat / path / user / detail")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--no-quarantine", action="store_true",
                   help="skip the Quarantine store")
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="RC4-unwrap the ResourceData files into DIR")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_defender.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_defender", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = collect(strpaths, want_quarantine=not a.no_quarantine)
    for s in res.sources:
        ctx.add_input(s)

    if a.extract:
        from windows_defender.quarantine import extract_all
        n = 0
        for sp in strpaths:
            q = Path(sp)
            for cand in ([q] + list(q.rglob("*")) if q.is_dir() else [q]):
                if cand.is_dir() and (cand / "ResourceData").is_dir():
                    for name, size in extract_all(cand, a.extract):
                        print(f"extracted {name} ({size} bytes)",
                              file=sys.stderr)
                        n += 1
        print(f"windows_defender: {n} resource(s) unwrapped into {a.extract}",
              file=sys.stderr)
    for e in res.errors:
        ctx.error("defender-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for r in res.rows:
        r.setdefault("event_id", "")
        r.setdefault("pid", "")
        r.setdefault("user", "")
        r.setdefault("process", "")
        r.setdefault("action", "")
        if a.kind and r.get("kind") != a.kind:
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
                "threat", "path", "user", "detail"))):
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
            print(f"{r.get('time') or '(no time)':<21} {r['kind']:<22} "
                  f"{(r.get('threat') or r.get('path') or '')[:52]}{mark}")
            if r.get("detail"):
                print(f"    {r['detail'][:160]}")
            for n in (r.get("notable") or "").split(";") if r.get("notable") \
                    else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r.get("notable"))
    print(f"windows_defender: {res.mplogs} MPLog, {res.evtx_files} evtx, "
          f"{res.quarantine_entries} quarantine entr(y/ies), {res.hives} "
          f"hive(s) -> {len(rows)} row(s), {fl} flagged "
          f"(worst: {flags.worst(rows)})", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
