from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

from acquisition_ram import __version__, capture, report
from acquisition_ram.capture import AcquisitionResult, Output


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acquisition_ram",
        description="Live memory acquisition: Linux physical RAM via "
                    "/proc/kcore -> LiME / raw / padded; Windows & macOS "
                    "collect the memory-bearing files (page file, hibernation, "
                    "crash dumps).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  acquisition_ram info\n"
            "  sudo acquisition_ram capture mem.lime --format lime\n"
            "  acquisition_ram capture out.raw --kcore ./kcore --iomem ./iomem\n"
            "  acquisition_ram capture ./ram_files --source /mnt/c --os windows\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"acquisition_ram {__version__}")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("methods", help="what each platform supports")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--source", metavar="ROOT",
                        help="collect memory-bearing files from this "
                             "filesystem root (a mounted image)")
    common.add_argument("--os", choices=["windows", "macos", "linux"],
                        help="OS of --source (default: guess)")
    common.add_argument("--kcore", default="/proc/kcore")
    common.add_argument("--iomem", default="/proc/iomem")

    i = sub.add_parser("info", parents=[common],
                       help="show what can be captured on this host / source")

    c = sub.add_parser("capture", parents=[common],
                       help="acquire memory (or the memory-bearing files)")
    c.add_argument("out", type=Path,
                   help="dump file (Linux kcore) or output directory (files)")
    c.add_argument("--format", choices=["lime", "raw", "padded"], default="lime",
                   help="Linux dump format (default lime)")
    c.add_argument("--only", type=lambda s: {x.strip() for x in s.split(",")},
                   metavar="CAT,CAT",
                   help="file collection: only these categories")
    c.add_argument("--hash", dest="algos", action="append", default=[],
                   choices=["md5", "sha1", "sha256"])
    c.add_argument("--case", dest="case_number", default="")
    c.add_argument("--evidence", dest="evidence_number", default="")
    c.add_argument("--examiner", default="")
    c.add_argument("--description", default="")
    c.add_argument("--notes", default="")
    c.add_argument("-q", "--quiet", action="store_true")
    return p


def _guess_os(root: Path) -> str:
    if (root / "Windows" / "System32").exists() or (root / "pagefile.sys").exists():
        return "windows"
    if (root / "System" / "Library" / "CoreServices").exists() or \
            (root / "private" / "var" / "vm").exists():
        return "macos"
    return "linux"


def _mode(a) -> str:
    if a.source:
        return a.os or _guess_os(Path(a.source))
    if a.kcore != "/proc/kcore" or a.iomem != "/proc/iomem":
        return "linux-offline"
    return {"Linux": "linux", "Windows": "windows",
            "Darwin": "macos"}.get(platform.system(), "files")


def _progress(quiet: bool, label: str):
    if quiet:
        return None
    state = {"t": 0.0}

    def cb(done, total):
        now = time.monotonic()
        if now - state["t"] < 0.5 and done < (total or 0):
            return
        state["t"] = now
        pct = f"{done / total * 100:5.1f}%" if total else "  ?  "
        sys.stderr.write(f"\r  {label}: {done} bytes ({pct})   ")
        sys.stderr.flush()
    return cb


def _meta(a) -> dict:
    return {"case_number": a.case_number, "evidence_number": a.evidence_number,
            "examiner": a.examiner, "description": a.description,
            "notes": a.notes, "version": __version__}


# ---------------------------------------------------------------- info
def _cmd_info(a) -> int:
    mode = _mode(a)
    if mode in ("linux", "linux-offline"):
        from acquisition_ram.linux import probe
        pr = probe(a.kcore, a.iomem)
        print(f"source        : {a.kcore} + {a.iomem}")
        print(f"kcore readable : {'yes' if pr.kcore_readable else 'NO'}")
        print(f"RAM ranges     : {len(pr.ram_ranges)}")
        for s, e in pr.ram_ranges[:20]:
            print(f"  {s:#014x} - {e:#014x}  ({(e - s) >> 20} MiB)")
        print(f"total RAM       : {pr.total_ram} ({pr.total_ram >> 20} MiB)")
        if pr.direct_map:
            print(f"PAGE_OFFSET     : {pr.page_offset:#018x}")
        print(f"ready to capture: {'YES' if pr.ok else 'no'}")
        for w in pr.warnings:
            print(f"  ! {w}", file=sys.stderr)
        return 0 if pr.ok else 1

    sources = _enum(mode, a.source)
    if not sources:
        print("no memory-bearing files found", file=sys.stderr)
        return 1
    print(f"{'category':<18} {'size':>14}  {'locked':<7} path")
    for s in sources:
        print(f"{s['category']:<18} {s['size']:>14}  "
              f"{'yes' if s.get('locked') else '':<7} {s['path']}")
    return 0


def _enum(mode: str, source: str | None):
    if mode == "windows":
        from acquisition_ram.win import enumerate_sources
    elif mode == "macos":
        from acquisition_ram.mac import enumerate_sources
    else:
        return []
    return enumerate_sources(source)


# ---------------------------------------------------------------- capture
def _cmd_capture(a) -> int:
    mode = _mode(a)
    algos = tuple(a.algos) or ("sha256", "sha1", "md5")
    meta = _meta(a)
    res = AcquisitionResult(method="", host_os=platform.platform(),
                            started=capture.now())
    t0 = time.monotonic()

    if mode in ("linux", "linux-offline"):
        rc = _capture_linux(a, algos, res)
    elif mode in ("windows", "macos"):
        rc = _capture_files(a, mode, algos, res)
    else:
        print(f"no driver-free memory acquisition on {platform.system()}; "
              "use --source against a mounted image, or --kcore/--iomem",
              file=sys.stderr)
        return 2

    res.seconds = round(time.monotonic() - t0, 2)
    res.finished = capture.now()
    _write_sidecars(a.out, res, meta, mode)
    if not a.quiet:
        print(report.text_log(res, meta))
    return rc


def _capture_linux(a, algos, res) -> int:
    from acquisition_ram.linux import capture as kcapture
    from acquisition_ram.linux import probe
    res.method = "linux-kcore"
    pr = probe(a.kcore, a.iomem)
    res.warnings = list(pr.warnings)
    res.total_ram = pr.total_ram
    if not pr.ok:
        res.warnings.append("FAILED: cannot read physical memory")
        print("cannot acquire: " + "; ".join(pr.warnings), file=sys.stderr)
        return 2
    hs = capture.new_hashers(algos)
    ranges, written, warns = kcapture(pr, str(a.out), a.format, hashers=hs,
                                      progress=_progress(a.quiet, a.format))
    if not a.quiet:
        sys.stderr.write("\n")
    res.ranges = ranges
    res.warnings += warns
    res.outputs.append(Output(name=a.out.name, path=str(a.out), size=written,
                              hashes=capture.digests(hs), category="memory",
                              note=f"{a.format} format"))
    if a.format == "raw":
        rj = a.out.with_suffix(a.out.suffix + ".ranges.json")
        import json
        rj.write_text(json.dumps(ranges, indent=2))
        res.outputs.append(Output(name=rj.name, path=str(rj),
                                  size=rj.stat().st_size,
                                  note="physical range map for the raw dump"))
    return 0


def _capture_files(a, mode, algos, res) -> int:
    res.method = f"{mode}-files"
    sources = _enum(mode, a.source)
    if not sources:
        res.warnings.append("FAILED: no memory-bearing files found")
        print("no memory-bearing files found", file=sys.stderr)
        return 1
    res.outputs = capture.collect_files(
        sources, a.out, algos=algos, only=a.only,
        progress=_progress(a.quiet, "copy"))
    if not a.quiet:
        sys.stderr.write("\n")
    locked = [o for o in res.outputs if not o.path]
    if locked:
        res.warnings.append(
            f"{len(locked)} file(s) locked - image the disk and re-run with "
            "--source against the mounted copy")
    return 0 if any(o.path for o in res.outputs) else 1


def _write_sidecars(out: Path, res, meta: dict, mode: str) -> None:
    base = out if (mode in ("windows", "macos")) else out.parent
    if mode in ("windows", "macos"):
        base.mkdir(parents=True, exist_ok=True)
        log_p = base / "acquisition_ram.txt"
        man_p = base / "acquisition_ram.json"
    else:
        log_p = out.with_suffix(out.suffix + ".txt")
        man_p = out.with_suffix(out.suffix + ".json")
    log_p.write_text(report.text_log(res, meta), encoding="utf-8")
    man_p.write_text(report.manifest(res, meta), encoding="utf-8")


def _cmd_methods(a) -> int:
    print("""platform  method
--------  ------------------------------------------------------------
Linux     /proc/kcore + /proc/iomem  ->  LiME / raw / padded dump
          (needs root; blocked by kernel lockdown - then use a VM
          snapshot or a kernel module such as LiME / AVML)
Windows   collect pagefile.sys, swapfile.sys, hiberfil.sys,
          MEMORY.DMP, Minidump\\*.dmp, CrashDumps\\*.dmp, WER dumps
          (locked live -> run against a mounted disk image with
          --source ROOT --os windows)
macOS     collect /private/var/vm/sleepimage + swapfile*, /cores,
          kernel panics (SIP blocks a live RAM read)
""")
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    return {"info": _cmd_info, "capture": _cmd_capture,
            "methods": _cmd_methods}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
