from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from linux_audit import __version__, tracelib
from linux_audit.analyze import analyze
from linux_audit.output import COLUMNS, render, row

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="linux_audit",
        description="Normalise the Linux audit daemon (auditd) logs under a "
                    "mounted image or a live root. Reassembles the multi-line "
                    "records by their msg=audit(...) event id into one "
                    "normalised event: syscall + outcome, reconstructed "
                    "command, executable, decoded proctitle, touched paths, "
                    "cwd, uid / auid / session, the audit key, and the actor "
                    "/ result for USER_* / AVC / account records. Decodes "
                    "hex fields and SOCKADDR records. Flags privilege "
                    "changes, auth failures, account changes, audit-rule "
                    "tampering, SELinux denials, execution from a writable "
                    "path and recon / cradle commands. Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  linux_audit /mnt/evidence\n"
                "  linux_audit / --action execve --csv exec.csv\n"
                "  linux_audit /mnt/img --notable-only --min-severity high\n"
                "  linux_audit /mnt/img --key sudoers --json k.json\n"
                "  linux_audit /var/log/audit/audit.log --grep nmap\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="filesystem root(s) to walk, or individual audit logs")
    p.add_argument("--version", action="version",
                   version=f"linux_audit {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--action", help="only this action (execve / auth / "
                   "user-cmd / account-change / selinux-denial / ...)")
    p.add_argument("--key", help="only events with this audit key (substring)")
    p.add_argument("--uid", help="only this uid")
    p.add_argument("--auid", help="only this auid (login uid)")
    p.add_argument("--grep", metavar="REGEX",
                   help="match command / exe / summary / paths")
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
        from linux_audit.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("at least one path is required (or use --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "linux_audit", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    res = analyze(strpaths)
    for f in res.files:
        ctx.add_input(f)
    for e in res.errors:
        ctx.error("audit-error", e)
    if res.unparsed:
        ctx.partial(f"{res.unparsed} line(s) did not match the audit record "
                    f"grammar and were skipped")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for ev in res.events:
        r = row(ev)
        if a.action and r["action"] != a.action:
            continue
        if a.key and a.key.lower() not in r["key"].lower():
            continue
        if a.uid and r["uid"] != a.uid:
            continue
        if a.auid and r["auid"] != a.auid:
            continue
        if a.since and (not r["ts"] or r["ts"][:10] < a.since):
            continue
        if a.until and (not r["ts"] or r["ts"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["command"], r["exe"], r["summary"], r["paths"]))):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        print(render(rows, res.actions), end="")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"linux_audit: {res.records} record(s) -> {len(res.events)} event(s) "
          f"from {len(res.files)} file(s) -> {len(rows)} shown, {fl} flagged",
          file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
