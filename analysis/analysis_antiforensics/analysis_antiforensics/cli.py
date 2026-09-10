from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_antiforensics import __version__, tracelib
from analysis_antiforensics.detectors import run_all
from analysis_antiforensics.load import load
from analysis_antiforensics.report import html_report

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["id", "severity", "title", "detail", "tool", "times", "evidence"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_antiforensics",
        description="Correlate anti-forensic / tampering indicators from the "
                    "other tools' CSV / JSON output into one findings list: "
                    "event-log clearing + record gaps, timestomping, "
                    "wiping-tool execution, history / journal clearing, "
                    "disabled telemetry, Defender being switched off, "
                    "$UsnJrnl truncation, deletion bursts and timeline gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  analysis_antiforensics ./case_outputs --html af.html\n"
                "  analysis_antiforensics evtx.csv mft.json usn.csv "
                "--json af.json\n"
                "  analysis_antiforensics ./out --min-severity medium\n"))
    p.add_argument("paths", nargs="+", type=Path,
                   help="CSV / JSON files or a directory of them")
    p.add_argument("--version", action="version",
                   version=f"analysis_antiforensics {__version__}")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high"],
                   default="info")
    p.add_argument("--html", type=Path)
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "analysis_antiforensics", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for s in strpaths:
        ctx.add_input(s)

    datasets = load(strpaths)
    if not datasets:
        print("no CSV / JSON datasets found", file=sys.stderr)
        return 2
    findings = [f for f in run_all(datasets)
                if _SEV[f.severity] >= _SEV[a.min_severity]]

    rows = [f.row() for f in findings]
    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="heuristic", tz="as-supplied")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="heuristic", tz="as-supplied")
    if a.html:
        a.html.write_text(html_report(findings, datasets), encoding="utf-8")

    if not a.quiet and not (a.csv or a.json or a.html):
        for d in datasets:
            print(f"  loaded {d.path}  -> {d.tool} ({len(d.rows)} rows)")
        print()
        for f in findings:
            print(f"[{f.severity.upper():<6}] {f.title}  ({f.tool})")
            print(f"         {f.detail}")
            for t in f.times:
                if t:
                    print(f"         @ {t}")
        if not findings:
            print("No anti-forensic indicators found.")

    ctx.finish(outputs=[a.csv, a.json, a.html])
    by = {}
    for f in findings:
        by[f.severity] = by.get(f.severity, 0) + 1
    print(f"analysis_antiforensics: {len(datasets)} dataset(s), "
          f"{len(findings)} finding(s) "
          f"({', '.join(f'{v} {k}' for k, v in by.items()) or 'none'})",
          file=sys.stderr)
    return 1 if any(f.severity in ("medium", "high") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
