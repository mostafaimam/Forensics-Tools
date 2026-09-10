from __future__ import annotations

import argparse
import sys
from pathlib import Path

from utilities_ole import __version__, tracelib
from utilities_ole.analyze import analyze
from utilities_ole.ole import OleError, OleFile

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["kind", "name", "value", "detail", "source"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utilities_ole",
        description="OLE2 compound-file and Office metadata extraction. "
                    "Lists the stream tree, parses SummaryInformation / "
                    "DocumentSummaryInformation (and OOXML core/app/custom) "
                    "properties, decompresses VBA macro source, lists "
                    "embedded objects and external relationship targets. "
                    "Flags macro auto-exec / shell / download constructs, "
                    "remote templates and author/last-saver mismatch.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  utilities_ole report.doc --props\n"
                "  utilities_ole invoice.xlsm --macros\n"
                "  utilities_ole deck.pptx --json meta.json\n"
                "  utilities_ole msg.msg --streams --extract ./out\n"))
    p.add_argument("files", nargs="+", type=Path,
                   help="OLE2 / OOXML file(s)")
    p.add_argument("--version", action="version",
                   version=f"utilities_ole {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--streams", action="store_true",
                   help="list the stream / package tree")
    p.add_argument("--props", action="store_true",
                   help="print the document properties")
    p.add_argument("--macros", action="store_true",
                   help="print the VBA macro source")
    p.add_argument("--extract", type=Path, metavar="DIR",
                   help="write every stream (OLE2) to DIR")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _extract_streams(path: str, dest: Path) -> int:
    try:
        ole = OleFile(Path(path).read_bytes())
    except (OleError, OSError):
        return 0
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for p, e in ole.walk():
        if e.entry_type != 2:
            continue
        safe = p.replace("\x05", "_05_").replace("/", "__").replace("\\", "_")
        try:
            (dest / safe).write_bytes(ole.read_path(p))
            n += 1
        except OleError:
            continue
    return n


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from utilities_ole.gui import run_gui
        return run_gui([str(p) for p in a.files])
    missing = [p for p in a.files if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2

    ctx = tracelib.context(a, "utilities_ole", __version__)
    strpaths = [str(p) for p in a.files]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    reports = []
    all_rows = []
    for sp in strpaths:
        ctx.add_input(sp)
        rep = analyze(sp)
        reports.append(rep)
        if rep.error:
            ctx.error("ole-error", f"{sp}: {rep.error}")
        for r in rep.rows():
            r["severity"] = rep.severity
            r["notable"] = ";".join(rep.notable)
            all_rows.append(r)
        if a.extract:
            _extract_streams(sp, a.extract / Path(sp).stem)

    rows = all_rows
    if a.notable_only:
        rows = [r for r in rows if r.get("notable")]
    if a.min_severity:
        rows = [r for r in rows
                if _SEV[r.get("severity", "none")] >= _SEV[a.min_severity]]

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS + ["severity", "notable"],
                           ctx, confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for rep in reports:
            _print_report(rep, a)

    ctx.finish(outputs=[a.csv, a.json])
    flagged = sum(1 for rep in reports if rep.notable)
    worst = "none"
    for rep in reports:
        if _SEV[rep.severity] > _SEV[worst]:
            worst = rep.severity
    print(f"utilities_ole: {len(reports)} file(s), {flagged} flagged "
          f"(worst: {worst})", file=sys.stderr)
    return 0 if reports else 1


def _print_report(rep, a) -> None:
    print(f"\n== {rep.path} ==")
    print(f"   container: {rep.container} {rep.doc_kind}".rstrip())
    if rep.error:
        print(f"   error: {rep.error}")
        return
    if rep.properties and (a.props or not (a.streams or a.macros)):
        print("   properties:")
        for k, v in rep.properties.items():
            print(f"     {k:<20} {v}")
    if a.streams:
        print("   streams:")
        for p, sz, knd in rep.streams:
            print(f"     {sz:>10}  {p}  {knd}")
    if rep.macros:
        print(f"   VBA: {len(rep.macro_modules)} module(s)")
        for name, lines, susp in rep.macro_modules:
            tag = f"  !! {', '.join(susp)}" if susp else ""
            print(f"     {name}  ({lines} lines){tag}")
            if a.macros:
                for mm in rep.macro_modules:
                    pass
    if a.macros:
        _dump_macros(rep)
    for e in rep.embedded:
        print(f"   embedded: {e}")
    for t in rep.external_targets:
        print(f"   external: {t}")
    for nn in rep.notable:
        print(f"   ! {nn}")


def _dump_macros(rep) -> None:
    from utilities_ole.analyze import analyze as _a  # noqa: F401
    # re-open to get source (analyze keeps only summaries)
    from utilities_ole.vba import extract as _vx
    try:
        data = Path(rep.path).read_bytes()
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            vp = _vx(OleFile(data))
        else:
            import zipfile
            from io import BytesIO
            zf = zipfile.ZipFile(BytesIO(data))
            binp = next(n for n in zf.namelist()
                        if n.endswith("vbaProject.bin"))
            vp = _vx(OleFile(zf.read(binp)))
    except Exception:  # noqa: BLE001
        return
    for m in vp.modules:
        if not m.source:
            continue
        print(f"\n   --- {m.name} ---")
        for line in m.source.splitlines():
            print(f"   {line}")


if __name__ == "__main__":
    raise SystemExit(main())
