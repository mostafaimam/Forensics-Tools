from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_view import __version__
from analysis_view.filters import apply_filters, apply_search, apply_sort
from analysis_view.htmlview import build_html
from analysis_view.model import Review, Table
from analysis_view.output import export_csv, export_json, render_table


def _parse_rule(s: str) -> dict:
    # "col~regex=#ffdddd"  or  "col~regex:red"
    col, _, rest = s.partition("~")
    match, sep, color = rest.rpartition("=") if "=" in rest else \
        rest.rpartition(":")
    if not sep:
        match, color = rest, "#ffe0e0"
    return {"col": col.strip(), "match": match.strip(),
            "color": color.strip() or "#ffe0e0"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_view",
        description="Review any tabular evidence (CSV / TSV / JSON / JSONL / "
                    "XLSX) in one place: merge sources, filter, sort, tag, "
                    "annotate, and export a self-contained interactive HTML "
                    "review page.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_view mft.csv evtx.csv --html review.html\n"
            "  analysis_view *.csv --filter 'severity=high' --export hi.csv\n"
            "  analysis_view t.csv --sort 'time:desc' --rule 'verdict~pe=#fdd'\n"
            "  analysis_view case.xlsx --gui\n"
        ),
    )
    p.add_argument("paths", nargs="*", type=Path)
    p.add_argument("--version", action="version",
                   version=f"analysis_view {__version__}")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--delim", help="force the CSV delimiter")
    p.add_argument("--sheet", help="xlsx sheet name (substring match)")
    p.add_argument("--filter", dest="filters", action="append", default=[],
                   metavar="COL OP VAL",
                   help="col=val / col~substr / col>=n / bare word (repeatable)")
    p.add_argument("--or", dest="filter_or", action="store_true",
                   help="OR the --filter clauses instead of AND")
    p.add_argument("--search", metavar="TEXT", help="full-text filter")
    p.add_argument("--sort", metavar="COL[:desc][,COL2…]")
    p.add_argument("--rule", action="append", default=[], metavar="COL~RX=#hex",
                   help="colour rows where COL matches RX (HTML only)")
    p.add_argument("--review", type=Path, metavar="FILE",
                   help="review sidecar (tags / notes / reviewed) to load "
                        "and, for --gui, save back to")
    p.add_argument("--html", type=Path, metavar="FILE")
    p.add_argument("--export", type=Path, metavar="FILE",
                   help="export the current view as CSV (or .json)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.paths and not a.gui:
        build_parser().error("at least one tabular file is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    if a.gui:
        from analysis_view.gui import run_gui
        return run_gui([str(p) for p in a.paths], review=a.review)

    try:
        table = Table.from_paths([str(p) for p in a.paths], delim=a.delim,
                                 sheet=a.sheet)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not table.rows:
        print("no rows loaded", file=sys.stderr)
        return 1

    review = Review.from_file(a.review) if a.review else Review()
    rules = [_parse_rule(r) for r in a.rule]

    rows = apply_filters(table.rows, a.filters,
                         "or" if a.filter_or else "and")
    rows = apply_search(rows, a.search)
    if a.sort:
        rows = apply_sort(rows, a.sort)

    cols = table.display_columns()
    if a.html:
        sub = Table(rows=rows, columns=table.columns, sources=table.sources)
        a.html.write_text(build_html(sub, review, rules=rules,
                                     title=a.html.stem), encoding="utf-8")
    if a.export:
        fn = export_json if a.export.suffix.lower() == ".json" else export_csv
        fn(rows, cols, a.export, review if a.review else None)
    if not (a.html or a.export) and not a.quiet:
        print(render_table(rows, cols), end="")

    print(f"analysis_view: {len(table.rows)} rows from {len(table.sources)} "
          f"source(s) -> {len(rows)} after filters", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
