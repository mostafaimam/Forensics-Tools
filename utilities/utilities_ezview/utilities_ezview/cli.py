from __future__ import annotations

import argparse
import sys
from pathlib import Path

from utilities_ezview import __version__, tracelib
from utilities_ezview.extract import render


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utilities_ezview",
        description="Zero-dependency viewer: sniff a file by content and "
                    "render it as text - plain text / logs (encoding "
                    "detected), CSV / TSV tables, HTML / MHTML (tag "
                    "stripped), RTF, and best-effort text from docx / xlsx "
                    "/ pptx / doc / xls / pdf. Unrenderable files fall back "
                    "to a hex + data-interpreter view.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  utilities_ezview report.docx\n"
                "  utilities_ezview export.xlsx --format\n"
                "  utilities_ezview note.rtf --text-out note.txt\n"
                "  utilities_ezview mystery.bin        # -> hex fallback\n"))
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--version", action="version",
                   version=f"utilities_ezview {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--format", action="store_true",
                   help="print only the detected format + notes")
    p.add_argument("--text-out", type=Path, metavar="FILE",
                   help="write the extracted text to FILE (single input)")
    p.add_argument("--max-chars", type=int, default=2_000_000)
    p.add_argument("--csv", type=Path,
                   help="one row per file: path, format, chars, note")
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from utilities_ezview.gui import run_gui
        return run_gui([str(p) for p in a.files])
    missing = [p for p in a.files if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "utilities_ezview", __version__)
    strpaths = [str(p) for p in a.files]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    rows = []
    for sp in strpaths:
        ctx.add_input(sp)
        v = render(sp, max_chars=a.max_chars)
        if v.error:
            ctx.error("ezview-error", f"{sp}: {v.error}")
        rows.append({"path": sp, "format": v.fmt, "encoding": v.encoding,
                     "chars": len(v.text), "truncated": v.truncated,
                     "note": v.note or v.error})
        if a.text_out and len(strpaths) == 1:
            a.text_out.write_text(v.text, encoding="utf-8")
        if not a.quiet and not (a.csv or a.json or a.text_out):
            hdr = f"===== {sp}  [{v.fmt}" + (f" / {v.encoding}"
                                             if v.encoding else "") + "] ====="
            print(hdr)
            if v.note:
                print(f"(note: {v.note})")
            if v.error:
                print(f"(error: {v.error})")
            if not a.format:
                print(v.text)
                if v.truncated:
                    print(f"\n... [truncated at {a.max_chars} chars] ...")
            print()

    if a.csv:
        tracelib.write_csv(rows, a.csv,
                           ["path", "format", "encoding", "chars",
                            "truncated", "note"], ctx,
                           confidence="medium", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="n/a")

    ctx.finish(outputs=[a.csv, a.json, a.text_out])
    unknown = sum(1 for r in rows if r["format"] in ("unknown", "binary"))
    print(f"utilities_ezview: {len(rows)} file(s), {unknown} not rendered "
          f"as text", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
