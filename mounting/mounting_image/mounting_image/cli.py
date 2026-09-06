from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from mounting_image import __version__
from mounting_image import attach
from mounting_image.formats import ImageError, SliceImage, open_image
from mounting_image.partitions import detect
from mounting_image.report import html_report, partition_rows, text_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_image",
        description="Read-only access to forensic disk images (raw / split / "
                    "E01 / VHD / VMDK): inspect the container and partitions, "
                    "export the disk or a partition as raw, stream a byte "
                    "range, or serve it over NBD.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  mounting_image info disk.E01\n"
            "  mounting_image partitions disk.E01 --json parts.json\n"
            "  mounting_image convert disk.E01 disk.raw\n"
            "  mounting_image extract disk.E01 --partition 2 --out part2.raw\n"
            "  mounting_image cat disk.vhd --offset 0 --size 512 | xxd\n"
            "  mounting_image serve disk.E01 --partition 2 --port 10809\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"mounting_image {__version__}")
    sub = p.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("image", type=Path)
    common.add_argument("--format", choices=["raw", "ewf", "vhd", "vhdx", "vmdk"],
                        help="force the container format")

    i = sub.add_parser("info", parents=[common], help="container + partitions")
    i.add_argument("--hash", choices=["md5", "sha1", "sha256"], action="append",
                   default=[], help="also hash the logical disk (repeatable)")
    i.add_argument("--html", type=Path, help="write an HTML report")
    i.add_argument("--json", type=Path)

    pp = sub.add_parser("partitions", parents=[common], help="partition table only")
    pp.add_argument("--json", type=Path)

    cv = sub.add_parser("convert", parents=[common],
                        help="decode the whole disk (or a partition) to raw")
    cv.add_argument("out", type=Path)
    cv.add_argument("--partition", type=int)

    ex = sub.add_parser("extract", parents=[common],
                        help="write one partition to a raw file")
    ex.add_argument("--partition", type=int, required=True)
    ex.add_argument("--out", type=Path, required=True)

    ct = sub.add_parser("cat", parents=[common], help="raw byte range to stdout")
    ct.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    ct.add_argument("--size", type=lambda x: int(x, 0), default=512)
    ct.add_argument("--partition", type=int)

    sv = sub.add_parser("serve", parents=[common], help="read-only NBD server")
    sv.add_argument("--partition", type=int)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=10809)
    sv.add_argument("--name", default="image")
    sv.add_argument("--attach", action="store_true",
                    help="also print (or run) the nbd-client/mount commands")
    sv.add_argument("--mountpoint")
    sv.add_argument("--fstype")
    sv.add_argument("--nbd-device", default="/dev/nbd0")
    sv.add_argument("--run", action="store_true",
                    help="actually execute the attach commands (needs root)")

    ls = sub.add_parser("list", help="show recorded NBD/mount sessions")
    un = sub.add_parser("unmount", help="tear down a recorded session")
    un.add_argument("--port", type=int, required=True)
    un.add_argument("--run", action="store_true")

    g = sub.add_parser("gui", help="open the graphical image browser")
    g.add_argument("image", type=Path, nargs="?")
    return p


def _open(a):
    fmt = getattr(a, "format", None)
    return open_image(a.image, fmt)


def _target(img, partition, scheme=None, parts=None):
    if partition is None:
        return img
    if parts is None:
        scheme, parts = detect(img)
    for p in parts:
        if p.index == partition:
            return SliceImage(img, p.start_offset, p.length,
                              label=f"partition {p.index}")
    raise ImageError(f"no partition {partition} (found {len(parts)})")


def _cmd_info(a) -> int:
    with _open(a) as img:
        scheme, parts = detect(img)
        meta = dict(getattr(img, "metadata", {}) or {})
        for algo in a.hash:
            h = hashlib.new(algo)
            for chunk in img.stream():
                h.update(chunk)
            meta[f"{algo}"] = h.hexdigest()
        print(text_report(img, scheme, parts, meta), end="")
        if a.html:
            a.html.write_text(html_report(img, scheme, parts, meta,
                                          a.image.name), encoding="utf-8")
            print(f"\nHTML report: {a.html}", file=sys.stderr)
        if a.json:
            import json
            a.json.write_text(json.dumps({
                "format": img.format_name,
                "subtype": getattr(img, "subtype", ""),
                "size": img.size, "sector_size": img.sector_size,
                "scheme": scheme, "metadata": meta,
                "partitions": partition_rows(parts)}, indent=2))
    return 0


def _cmd_partitions(a) -> int:
    with _open(a) as img:
        scheme, parts = detect(img)
        rows = partition_rows(parts)
        if a.json:
            import json
            a.json.write_text(json.dumps(
                {"scheme": scheme, "partitions": rows}, indent=2))
        else:
            print(text_report(img, scheme, parts))
    return 0 if parts else 1


def _write_raw(src, out: Path) -> int:
    total = 0
    with out.open("wb") as fh:
        for chunk in src.stream():
            fh.write(chunk)
            total += len(chunk)
    print(f"wrote {total} bytes -> {out}", file=sys.stderr)
    return 0


def _cmd_convert(a) -> int:
    with _open(a) as img:
        return _write_raw(_target(img, a.partition), a.out)


def _cmd_extract(a) -> int:
    with _open(a) as img:
        return _write_raw(_target(img, a.partition), a.out)


def _cmd_cat(a) -> int:
    with _open(a) as img:
        tgt = _target(img, a.partition)
        remaining = a.size
        pos = a.offset
        buf = sys.stdout.buffer
        while remaining > 0:
            n = min(remaining, 1 << 20)
            data = tgt.read(pos, n)
            if not data:
                break
            buf.write(data)
            pos += len(data)
            remaining -= len(data)
    return 0


def _cmd_serve(a) -> int:
    from mounting_image.nbd import NBDServer
    img = _open(a)
    tgt = _target(img, a.partition)
    srv = NBDServer(tgt, a.host, a.port, a.name)
    print(f"NBD export '{a.name}' ({tgt.size} bytes) on {a.host}:{a.port}",
          file=sys.stderr)
    if a.attach or a.run:
        cmds = attach.plan_attach(str(a.image), a.port, a.name, a.host,
                                  a.nbd_device, a.mountpoint, a.fstype)
        if not cmds:
            print("attach: only supported on Linux with nbd-client",
                  file=sys.stderr)
        else:
            print("\n".join("  " + " ".join(c) for c in cmds), file=sys.stderr)
            if a.run:
                if not attach.is_root():
                    print("attach --run needs root", file=sys.stderr)
                    return 2
                srv.serve_in_thread()
                ok, log = attach.run(cmds)
                print(log, file=sys.stderr)
                if ok:
                    attach.register(attach.Session(
                        str(a.image), a.partition, a.name, a.host, a.port,
                        a.nbd_device, a.mountpoint or ""))
                    print("attached; run 'mounting_image unmount --port "
                          f"{a.port} --run' to detach", file=sys.stderr)
                try:
                    srv.serve_forever()
                except KeyboardInterrupt:
                    pass
                return 0
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    finally:
        srv.server_close()
        img.close()
    return 0


def _cmd_list(a) -> int:
    rows = attach.sessions()
    if not rows:
        print("no recorded sessions", file=sys.stderr)
        return 1
    for r in rows:
        print(f"port {r['port']:<6} {r['export_name']:<12} "
              f"{r.get('nbd_device', ''):<12} {r.get('mountpoint', ''):<20} "
              f"{r['image']}")
    return 0


def _cmd_unmount(a) -> int:
    row = attach.deregister(a.port)
    if not row:
        print(f"no session on port {a.port}", file=sys.stderr)
        return 1
    cmds = attach.plan_detach(row.get("nbd_device", ""), row.get("mountpoint"))
    print("\n".join("  " + " ".join(c) for c in cmds) or "(nothing to do)",
          file=sys.stderr)
    if a.run and cmds:
        ok, log = attach.run(cmds)
        print(log, file=sys.stderr)
        return 0 if ok else 1
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if a.cmd == "gui":
        from mounting_image.gui import run
        return run(str(a.image) if a.image else None)
    if a.cmd in ("list", "unmount"):
        return {"list": _cmd_list, "unmount": _cmd_unmount}[a.cmd](a)
    if not a.image.exists():
        print(f"image not found: {a.image}", file=sys.stderr)
        return 2
    try:
        return {
            "info": _cmd_info, "partitions": _cmd_partitions,
            "convert": _cmd_convert, "extract": _cmd_extract,
            "cat": _cmd_cat, "serve": _cmd_serve,
        }[a.cmd](a)
    except ImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
