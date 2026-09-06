from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

from analysis_email import __version__
from analysis_email.formats import detect, parse_file

_COLUMNS = ["source", "container", "index", "date", "delivered", "from_name",
            "from_addr", "to", "cc", "bcc", "subject", "message_id",
            "reply_to", "return_path", "x_originating_ip", "attachment_count",
            "attachments", "body_bytes", "has_html", "flags"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iter(paths, recurse):
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in (p.rglob("*") if recurse else p.glob("*")):
                if f.is_file() and f.suffix.lower() in (
                        ".eml", ".msg", ".mbox", ".mbx", ".pst", ".ost") \
                        or (f.is_file() and detect(f) in
                            ("eml", "msg", "mbox", "pst")):
                    yield f


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_email",
        description="Inventory email: MBOX / EML / Outlook MSG -> one row per "
                    "message with headers, addresses, dates, attachments "
                    "(name + SHA-256), and spoofing / auth-failure flags. "
                    "(PST / OST: export to MBOX first.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_email scan /cases/mail --csv messages.csv\n"
            "  analysis_email scan inbox.mbox --attachments-dir ./att\n"
            "  analysis_email scan suspicious.msg --json msg.json\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_email {__version__}")
    s = p.add_subparsers(dest="cmd")
    sc = s.add_parser("scan", help="parse mail files / folders")
    sc.add_argument("paths", nargs="+", type=Path)
    sc.add_argument("--no-recurse", action="store_true")
    sc.add_argument("--attachments-dir", type=Path,
                    help="also carve attachments to this directory")
    sc.add_argument("--with-attachments-only", action="store_true")
    sc.add_argument("--flagged-only", action="store_true",
                    help="only messages with a spoofing / auth flag")
    sc.add_argument("--grep", metavar="REGEX",
                    help="keep messages whose subject / body match")
    sc.add_argument("--csv", type=Path)
    sc.add_argument("--json", type=Path)
    sc.add_argument("-q", "--quiet", action="store_true")
    return p


def _cmd_scan(a) -> int:
    import re
    rx = re.compile(a.grep, re.IGNORECASE) if a.grep else None
    rows, errors, msgs = [], 0, 0
    att_saved = 0
    for f in _iter([str(x) for x in a.paths], not a.no_recurse):
        try:
            batch = parse_file(str(f))
        except NotImplementedError as e:
            print(f"! {f}: {e}", file=sys.stderr)
            errors += 1
            continue
        except (ValueError, OSError) as e:
            print(f"! {f}: {e}", file=sys.stderr)
            errors += 1
            continue
        for m in batch:
            msgs += 1
            if a.with_attachments_only and not m.attachments:
                continue
            if a.flagged_only and not m.flags:
                continue
            if rx and not (rx.search(m.subject or "") or
                           rx.search(m.body_preview or "")):
                continue
            rows.append(m.as_row())
            if a.attachments_dir:
                att_saved += _save_attachments(f, m, a.attachments_dir)

    if a.csv:
        with a.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_COLUMNS, dialect="excel")
            w.writeheader()
            for r in rows:
                w.writerow({k: _san(r.get(k, "")) for k in _COLUMNS})
    if a.json:
        a.json.write_text(json.dumps(rows, indent=2, default=str))
    if not a.quiet and not (a.csv or a.json):
        print(_render(rows), end="")

    flagged = sum(1 for r in rows if r["flags"])
    with_att = sum(1 for r in rows if r["attachment_count"])
    print(f"analysis_email: {msgs} message(s), {flagged} flagged, "
          f"{with_att} with attachments"
          + (f", {att_saved} attachment(s) saved" if a.attachments_dir else "")
          + (f", {errors} file error(s)" if errors else ""), file=sys.stderr)
    return 1 if flagged else 0


def _save_attachments(src: Path, m, outdir: Path) -> int:
    if not m.attachments:
        return 0
    sub = outdir / (src.stem + f"_{m.index:04d}")
    sub.mkdir(parents=True, exist_ok=True)
    n = 0
    for att in m.attachments:
        safe = "".join(c for c in att.name if c not in '\\/:*?"<>|') \
            or f"att{n}"
        (sub / f"{att.sha256[:12]}_{safe}").write_bytes(att.data)
        n += 1
    return n


def _render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        flag = "  [!]" if r["flags"] else ""
        out.write(f"{r['date'] or '?':<21} {r['from_addr'][:32]:<32} "
                  f"{(r['subject'] or '')[:50]}{flag}\n")
        if r["attachment_count"]:
            out.write(f"    attachments: {r['attachments']}\n")
        if r["flags"]:
            out.write(f"    flags: {r['flags']}\n")
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd != "scan":
        build_parser().print_help()
        return 2
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2
    return _cmd_scan(a)


if __name__ == "__main__":
    raise SystemExit(main())
