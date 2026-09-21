from __future__ import annotations

import sys
import argparse
from pathlib import Path

from cloud_cloudtrail import __version__, tracelib
from cloud_cloudtrail.collect import collect
from cloud_cloudtrail.flatten import COLUMNS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud_cloudtrail",
        description="Normalise AWS CloudTrail logs (.json / .json.gz "
                    "delivery files, or an export directory) into one row "
                    "per API call: identity, source IP, region, service, "
                    "action, error code. Flags IAM changes, ConsoleLogin "
                    "without MFA, secrets access, public-ACL/policy "
                    "changes, root-account usage, and Delete* bursts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  cloud_cloudtrail 123456-CloudTrail-2026-01-01.json.gz\n"
                "  cloud_cloudtrail ./cloudtrail-export --notable-only "
                "--csv events.csv\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a CloudTrail file, or a directory to search "
                   "recursively")
    p.add_argument("--version", action="version",
                   version=f"cloud_cloudtrail {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--event-name", help="substring filter on event name")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from cloud_cloudtrail.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "cloud_cloudtrail", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect([a.target])
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.event_name:
        rows = [r for r in rows
               if a.event_name.lower() in r["event_name"].lower()]
    if a.notable_only:
        rows = [r for r in rows if r["notable"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = f"  [{r['notable']}]" if r["notable"] else ""
            print(f"{r['event_time']}  {r['event_name']:<24} "
                 f"{r['principal_arn'] or r['user_name']}  "
                 f"{r['source_ip']}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"cloud_cloudtrail: {len(rows)} event(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
