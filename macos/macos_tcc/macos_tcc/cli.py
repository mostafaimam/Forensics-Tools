from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_tcc import __version__, tracelib
from macos_tcc import flags as _flags
from macos_tcc.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["scope", "service", "service_raw", "client", "client_type",
           "decision", "auth_reason", "indirect_object", "last_modified",
           "from_profile", "severity", "source", "notable"]


def _discover(p: Path):
    if p.is_file():
        return [(p, "")]
    out = []
    for q in p.rglob("TCC.db"):
        if not (q.is_file() and "com.apple.TCC" in str(q)):
            continue
        try:
            rel = q.relative_to(p).as_posix().lower()
        except ValueError:
            rel = q.as_posix().lower()
        scope = "user" if rel.startswith(("users/", "home/")) \
            or "/users/" in "/" + rel else "system"
        out.append((q, scope))
    return sorted(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_tcc",
        description="Parse the TCC.db privacy-permission database (system "
                    "and per-user). One row per grant: scope, the service "
                    "in plain language, the client (bundle id or path), the "
                    "decision (allowed / denied / limited), the auth reason, "
                    "the indirect object for Automation grants, the "
                    "last-modified time (UTC), and whether it came from a "
                    "configuration profile. Handles the auth_value and older "
                    "'allowed' schemas. Flags high-impact permissions "
                    "granted to CLI / scripting tools, keystroke-monitoring "
                    "grants and clients in user-writable paths. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_tcc TCC.db --csv tcc.csv\n"
                "  macos_tcc /Volumes/Macintosh\\ HD   (a mounted volume)\n"
                "  macos_tcc TCC.db --service Accessibility --decision allowed\n"
                "  macos_tcc TCC.db --notable-only --min-severity high\n"))
    p.add_argument("path", type=Path, help="a TCC.db or a mounted macOS "
                   "volume")
    p.add_argument("--version", action="version",
                   version=f"macos_tcc {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--service", help="substring match on the service name")
    p.add_argument("--client", help="substring match on the client")
    p.add_argument("--decision", choices=["allowed", "denied", "limited"])
    p.add_argument("--scope", choices=["system", "user"])
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
        from macos_tcc.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_tcc", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no TCC.db found", file=sys.stderr)
        return 2

    grants = []
    for db, scope in dbs:
        ctx.add_input(str(db))
        try:
            grants += parse(str(db), scope)
        except Exception as e:                    # noqa: BLE001
            ctx.error("tcc-error", f"{db}: {e}")

    rows = []
    for g in grants:
        r = g.row()
        r["severity"] = _flags.severity(g.notable)
        if a.service and a.service.lower() not in r["service"].lower():
            continue
        if a.client and a.client.lower() not in r["client"].lower():
            continue
        if a.decision and r["decision"] != a.decision:
            continue
        if a.scope and r["scope"] != a.scope:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
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
            io = f" -> {r['indirect_object']}" if r["indirect_object"] else ""
            print(f"{r['scope']:<6} {r['decision']:<8} {r['service']:<32} "
                  f"{r['client']}{io}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_tcc: {len(grants)} grant(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
