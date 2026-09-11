from __future__ import annotations

import argparse
import sys
from pathlib import Path

from windows_sigma import __version__, tracelib
from windows_sigma.engine import run_rules
from windows_sigma.rules import RuleError, load_dir, load_file

_BUNDLED = Path(__file__).parent / "rules"
COLUMNS = ["rule", "rule_id", "level", "tags", "time", "matched", "source"]
_LEVELS = ["informational", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_sigma",
        description="A lightweight Sigma-style detection-rules engine. Runs "
                    "a bundled starter ruleset (plus --rule-dir) against the "
                    "normalised CSV / JSON output of windows_evtx / "
                    "windows_pslogging and reports each hit with the rule "
                    "name, level and matched fields.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_sigma evtx.csv --csv hits.csv\n"
                "  windows_sigma pslog.csv evtx.csv --rule-dir ./my_rules\n"
                "  windows_sigma evtx.json --min-level high\n"
                "  windows_sigma --list-rules\n"))
    p.add_argument("inputs", nargs="*", type=Path,
                   help="CSV / JSON / JSONL exports to scan")
    p.add_argument("--version", action="version",
                   version=f"windows_sigma {__version__}")
    p.add_argument("--rule", type=Path, action="append", default=[],
                   metavar="FILE", help="one additional rule file; repeatable")
    p.add_argument("--rule-dir", type=Path, action="append", default=[],
                   metavar="DIR", help="a directory of *.yml rules; "
                                       "repeatable")
    p.add_argument("--no-bundled", action="store_true",
                   help="skip the bundled starter ruleset")
    p.add_argument("--list-rules", action="store_true",
                   help="print the loaded rules and exit")
    p.add_argument("--min-level", choices=_LEVELS, default="informational")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _load_rules(a):
    rules, errors = [], []
    if not a.no_bundled:
        r, e = load_dir(str(_BUNDLED))
        rules += r
        errors += e
    for f in a.rule:
        try:
            rules.append(load_file(str(f)))
        except RuleError as e:
            errors.append(f"{f}: {e}")
    for d in a.rule_dir:
        r, e = load_dir(str(d))
        rules += r
        errors += e
    return rules, errors


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    rules, rule_errors = _load_rules(a)
    if a.list_rules:
        for r in rules:
            print(f"{r.level:<9} {r.title}  [{r.condition_text}]  "
                  f"({r.source})")
        for e in rule_errors:
            print(f"  ! bad rule: {e}", file=sys.stderr)
        return 0
    if not a.inputs:
        build_parser().error("give at least one input file (or --list-rules)")
    missing = [p for p in a.inputs if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2
    if not rules:
        print("no rules loaded", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_sigma", __version__)
    strpaths = [str(p) for p in a.inputs]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for s in strpaths:
        ctx.add_input(s)
    for e in rule_errors:
        ctx.error("sigma-rule-error", e)

    hits = run_rules(rules, strpaths, min_level=a.min_level)
    rows = [h.row_out() for h in hits]

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="as-supplied")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="as-supplied")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            print(f"[{r['level'].upper():<13}] {r['rule']}  ({r['source']})")
            if r["time"]:
                print(f"    @ {r['time']}")
            if r["matched"]:
                print(f"    {r['matched']}")
            if r["tags"]:
                print(f"    tags: {r['tags']}")

    ctx.finish(outputs=[a.csv, a.json])
    by_level = {}
    for r in rows:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
    print(f"windows_sigma: {len(rules)} rule(s), {len(rows)} hit(s) "
          f"({', '.join(f'{v} {k}' for k, v in by_level.items()) or 'none'})",
          file=sys.stderr)
    return 1 if any(r["level"] in ("high", "critical") for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
