from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analysis_report import __version__
from analysis_report.ingest import load
from analysis_report.render import build_bundle, build_html


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_report",
        description="Bundle tool output (CSV / JSON) + Markdown notes into one "
                    "self-contained HTML case report (and a JSON bundle).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_report build case.html --title 'Case 2026-014' \\\n"
            "      --input timeline.csv --input kff_hits.csv --note findings.md \\\n"
            "      --case 2026-014 --examiner 'A. Analyst'\n"
            "  analysis_report build out.html --input ./exports/\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_report {__version__}")
    s = p.add_subparsers(dest="cmd")
    b = s.add_parser("build", help="generate the report")
    b.add_argument("out", type=Path, help="output .html path")
    b.add_argument("--title", default="Case report")
    b.add_argument("--input", "-i", action="append", default=[], type=Path,
                   metavar="PATH", help="a CSV/JSON file or a directory of them")
    b.add_argument("--note", type=Path, action="append", default=[],
                   help="a Markdown notes file (repeatable, concatenated)")
    b.add_argument("--case", dest="case_number", default="")
    b.add_argument("--evidence", dest="evidence_number", default="")
    b.add_argument("--examiner", default="")
    b.add_argument("--organization", default="")
    b.add_argument("--summary", default="", help="one-line case summary")
    b.add_argument("--max-rows", type=int, default=500,
                   help="max rows rendered per source table (default 500)")
    b.add_argument("--json", type=Path, help="also write a JSON bundle here")
    b.add_argument("-q", "--quiet", action="store_true")
    return p


def _expand(inputs) -> list[Path]:
    out = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            out += sorted(f for f in p.rglob("*")
                          if f.suffix.lower() in (".csv", ".json", ".jsonl"))
        elif p.is_file():
            out.append(p)
        else:
            print(f"! not found: {p}", file=sys.stderr)
    return out


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd != "build":
        build_parser().print_help()
        return 2
    files = _expand(a.input)
    if not files:
        print("no input files", file=sys.stderr)
        return 2

    sources = []
    for f in files:
        try:
            sources.append(load(str(f)))
        except (ValueError, OSError, json.JSONDecodeError) as e:
            print(f"! {f}: {e}", file=sys.stderr)
    if not sources:
        print("nothing could be loaded", file=sys.stderr)
        return 2

    notes = "\n\n".join(p.read_text(encoding="utf-8", errors="replace")
                        for p in a.note if p.exists())
    meta = {k: v for k, v in {
        "case_number": a.case_number, "evidence_number": a.evidence_number,
        "examiner": a.examiner, "organization": a.organization,
        "summary": a.summary}.items() if v}

    a.out.write_text(build_html(title=a.title, meta=meta, sources=sources,
                                notes_md=notes, max_rows=a.max_rows),
                     encoding="utf-8")
    if a.json:
        a.json.write_text(json.dumps(
            build_bundle(title=a.title, meta=meta, sources=sources,
                         notes_md=notes), indent=2, default=str),
            encoding="utf-8")

    rows = sum(s.row_count for s in sources)
    alerts = sum(s.alert_rows for s in sources)
    if not a.quiet:
        print(f"analysis_report: {len(sources)} source(s), {rows} rows, "
              f"{alerts} alert rows -> {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
