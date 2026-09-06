from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from acquisition_image import __version__
from acquisition_image import devices as _devices
from acquisition_image.imager import acquire, verify
from acquisition_image.report import html_report, manifest, text_log
from acquisition_image.source import SourceError


def _size(s: str) -> int:
    s = s.strip().lower()
    mult = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s, 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acquisition_image",
        description="Create and verify forensic disk images (raw / split raw / "
                    "EWF E01) with streaming hashing, bad-sector tolerance, an "
                    "acquisition log and a JSON manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  acquisition_image disks\n"
            "  acquisition_image acquire /dev/sdb evidence.E01 --format ewf \\\n"
            "      --case 2026-014 --examiner 'A. Analyst' --verify\n"
            "  acquisition_image acquire disk.dd out.raw --split 2G\n"
            "  acquisition_image verify evidence.E01\n"
            "  acquisition_image hash /dev/sdb\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"acquisition_image {__version__}")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("disks", help="list local physical disks")

    g = sub.add_parser("gui", help="open the acquisition wizard")

    ac = sub.add_parser("acquire", help="read a source and write an image")
    ac.add_argument("source")
    ac.add_argument("output", type=Path)
    ac.add_argument("--format", choices=["raw", "split", "ewf", "e01"],
                    default="raw")
    ac.add_argument("--split", type=_size, metavar="SIZE",
                    help="raw: split into segments of this size (implies --format split)")
    ac.add_argument("--segment-size", type=_size, metavar="SIZE",
                    help="ewf: roll to a new .E0x segment at this size")
    ac.add_argument("--compression", choices=["none", "fast", "best"],
                    default="fast", help="ewf chunk compression (default fast)")
    ac.add_argument("--sector-size", type=int, default=512)
    ac.add_argument("--offset", type=_size, default=0)
    ac.add_argument("--length", type=_size, default=None)
    ac.add_argument("--verify", action="store_true",
                    help="re-read the written image and compare hashes")
    ac.add_argument("--case", dest="case_number", default="")
    ac.add_argument("--evidence", dest="evidence_number", default="")
    ac.add_argument("--examiner", default="")
    ac.add_argument("--description", default="")
    ac.add_argument("--notes", default="")
    ac.add_argument("-q", "--quiet", action="store_true")

    ve = sub.add_parser("verify", help="re-hash an image (and check its digest)")
    ve.add_argument("image")
    ve.add_argument("--format", choices=["raw", "ewf", "e01"])
    ve.add_argument("--md5")
    ve.add_argument("--sha1")
    ve.add_argument("--sha256")
    ve.add_argument("-q", "--quiet", action="store_true")

    ha = sub.add_parser("hash", help="hash a source without imaging it")
    ha.add_argument("source")
    ha.add_argument("--sector-size", type=int, default=512)
    return p


def _progress(quiet: bool):
    if quiet:
        return None
    state = {"t": 0.0}

    def cb(done, total, elapsed):
        now = time.monotonic()
        if now - state["t"] < 0.5 and done < total:
            return
        state["t"] = now
        pct = (done / total * 100) if total else 0
        rate = done / elapsed / (1 << 20) if elapsed else 0
        sys.stderr.write(f"\r  {done}/{total} bytes ({pct:5.1f}%)  "
                         f"{rate:6.1f} MiB/s   ")
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\n")
    return cb


def _meta(a) -> dict:
    return {"case_number": a.case_number, "evidence_number": a.evidence_number,
            "examiner": a.examiner, "description": a.description,
            "notes": a.notes, "version": __version__}


def _cmd_disks(a) -> int:
    disks = _devices.list_disks()
    if not disks:
        print("no disks enumerated (need privileges, or unsupported platform)",
              file=sys.stderr)
        return 1
    for d in disks:
        print(f"{d['path']:<22} {d['size_h']:>10}  {d.get('model','')}"
              f"{'  [removable]' if d.get('removable') else ''}")
        for part in d.get("partitions", []):
            print(f"    {part}")
    return 0


def _cmd_acquire(a) -> int:
    fmt = "split" if a.split else a.format
    ewf = fmt in ("ewf", "e01")
    try:
        res = acquire(a.source, str(a.output),
                      fmt="ewf" if ewf else "raw",
                      split_size=a.split if fmt == "split" else None,
                      segment_size=a.segment_size, compression=a.compression,
                      sector_size=a.sector_size, offset=a.offset,
                      length=a.length, metadata=_meta(a),
                      progress=_progress(a.quiet))
    except SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    res.fmt = fmt
    meta = _meta(a)

    if a.verify:
        if not a.quiet:
            print("verifying...", file=sys.stderr)
        v = verify(res.segments[0] if res.segments else str(a.output),
                   fmt="ewf" if ewf else "raw", expected=res.hashes,
                   progress=_progress(a.quiet))
        res.verify_hashes = {k: v[k] for k in ("md5", "sha1", "sha256")
                             if k in v}
        res.verified = "ok" if v["match"] else "MISMATCH"

    log = text_log(res, meta)
    base = Path(res.segments[0]) if res.segments else a.output
    log_path = base.with_suffix(base.suffix + ".txt")
    log_path.write_text(log, encoding="utf-8")
    man_path = base.with_suffix(base.suffix + ".json")
    man_path.write_text(manifest(res, meta), encoding="utf-8")
    html_path = base.with_suffix(base.suffix + ".html")
    html_path.write_text(html_report(res, meta), encoding="utf-8")

    if not a.quiet:
        print(log)
        print(f"log: {log_path}\nmanifest: {man_path}\nreport: {html_path}",
              file=sys.stderr)
    return 0 if res.ok else 1


def _cmd_verify(a) -> int:
    expected = {k: v for k, v in (("md5", a.md5), ("sha1", a.sha1),
                                  ("sha256", a.sha256)) if v}
    try:
        v = verify(a.image, fmt=a.format, expected=expected or None,
                   progress=_progress(a.quiet))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for algo in ("md5", "sha1", "sha256"):
        if algo in v:
            print(f"  {algo.upper():<7}: {v[algo]}")
    if v["stored"]:
        print(f"  embedded : {v['stored']}")
    print(f"\ncompared against {v['compared_against']}: "
          f"{'MATCH' if v['match'] else 'NO MATCH' if v['compared_against'] != 'nothing (no reference)' else 'n/a'}")
    return 0 if v["match"] or not expected and not v["stored"] else 1


def _cmd_hash(a) -> int:
    import hashlib
    from acquisition_image.source import Source
    try:
        src = Source(a.source, a.sector_size)
    except SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    digests = {x: hashlib.new(x) for x in ("md5", "sha1", "sha256")}
    cb = _progress(False)
    pos, total = 0, src.size
    while pos < total:
        data = src.read(pos, min(1 << 20, total - pos))
        for d in digests.values():
            d.update(data)
        pos += len(data)
        if cb:
            cb(pos, total, 0)
    src.close()
    print(f"  size    : {total}")
    for algo in ("md5", "sha1", "sha256"):
        print(f"  {algo.upper():<7}: {digests[algo].hexdigest()}")
    if src.bad_ranges:
        print(f"  bad regions: {len(src.bad_ranges)} (zero-filled)")
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if a.cmd == "gui":
        from acquisition_image.gui import run
        return run()
    return {
        "disks": _cmd_disks, "acquire": _cmd_acquire,
        "verify": _cmd_verify, "hash": _cmd_hash,
    }[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
