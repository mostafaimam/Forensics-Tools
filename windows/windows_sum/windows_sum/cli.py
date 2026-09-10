from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_sum import __version__, flags, tracelib
from windows_sum.analyze import analyze

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["last_seen", "first_seen", "role", "user", "client_name",
           "address", "tenant", "total_accesses", "total_seconds", "daily",
           "insert_date", "severity", "notable", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_sum",
        description="Microsoft User Access Logging (SUM) forensics. Reads "
                    "SystemIdentity.mdb (role GUID -> product name, host "
                    "identity) and the Current.mdb / {GUID}.mdb role "
                    "databases, and emits one row per (user, client, role) "
                    "access aggregate: authenticated user, client name / IP, "
                    "role, first / last seen, total accesses and duration, "
                    "and the per-day access histogram. Flags access from "
                    "public IPs, machine / privileged accounts and "
                    "single-day spikes. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_sum C:/Windows/System32/LogFiles/SUM --csv sum.csv\n"
                "  windows_sum Current.mdb SystemIdentity.mdb --json sum.json\n"
                "  windows_sum E:\\ --notable-only --min-severity medium\n"
                "  windows_sum SUM --user administrator\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="the SUM folder, .mdb file(s), or a mount root")
    p.add_argument("--version", action="version",
                   version=f"windows_sum {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--user", metavar="SUBSTR", help="match the user name")
    p.add_argument("--role", metavar="SUBSTR", help="match the role name")
    p.add_argument("--address", metavar="SUBSTR", help="match the client IP")
    p.add_argument("--grep", metavar="REGEX",
                   help="match user / client / address / role")
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
        from windows_sum.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "windows_sum", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for s in res.sources:
        ctx.add_input(s)
    for e in res.errors:
        ctx.error("sum-error", e)

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for acc in res.rows:
        n, s = flags.classify(acc)
        acc.notable = n
        r = acc.row()
        r["severity"] = s
        if a.user and a.user.lower() not in (r["user"] or "").lower():
            continue
        if a.role and a.role.lower() not in (r["role"] or "").lower():
            continue
        if a.address and a.address not in (r["address"] or ""):
            continue
        t = (r["last_seen"] or "")[:10]
        if a.since and (not t or t < a.since):
            continue
        if a.until and (not t or t > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join(str(r.get(k, "")) for k in (
                "user", "client_name", "address", "role"))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="local-as-recorded")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="local-as-recorded")
    if not a.quiet and not (a.csv or a.json):
        if res.identity:
            print("host identity:", ", ".join(
                f"{k}={v}" for k, v in list(res.identity.items())[:8]),
                file=sys.stderr)
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            print(f"{r['last_seen'] or '(no time)':<21} {r['role'][:28]:<28} "
                  f"{r['user'] or '(no user)':<24} {r['address']}"
                  f"  x{r['total_accesses']}{mark}")
            if r["daily"]:
                print(f"    {r['daily'][:180]}")
            for nn in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {nn}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_sum: {res.dbs} role DB(s), {len(res.roles)} role name(s) "
          f"-> {len(rows)} access row(s), {fl} flagged "
          f"(worst: {flags.worst(rows)})", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
