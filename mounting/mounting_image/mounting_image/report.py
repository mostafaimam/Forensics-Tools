"""Human and HTML descriptions of an image and its partitions."""

from __future__ import annotations

import html
import io

from mounting_image.formats.base import Image
from mounting_image.partitions import Partition


def _si(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024 or unit == "PiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def partition_rows(parts: list[Partition]) -> list[dict]:
    rows = []
    for p in parts:
        rows.append({
            "index": p.index,
            "scheme": p.scheme,
            "type": p.type_label,
            "type_code": p.type_code,
            "name": p.name,
            "start_offset": p.start_offset,
            "start_lba": p.start_lba,
            "length": p.length,
            "size": _si(p.length),
            "bootable": "yes" if p.bootable else "",
        })
    return rows


def text_report(img: Image, scheme: str, parts: list[Partition],
                meta: dict | None = None) -> str:
    out = io.StringIO()
    out.write(f"format        : {img.format_name}\n")
    if getattr(img, "subtype", ""):
        out.write(f"subtype       : {img.subtype}\n")
    out.write(f"logical size  : {img.size} bytes ({_si(img.size)})\n")
    out.write(f"sector size   : {img.sector_size}\n")
    if getattr(img, "segment_count", 0) > 1:
        out.write(f"segments      : {img.segment_count}\n")
    for k, v in (meta or {}).items():
        out.write(f"{k:<14}: {v}\n")
    out.write(f"partitioning  : {scheme}\n")
    if not parts:
        out.write("  (no partition table - the image may be a single volume)\n")
        return out.getvalue()
    out.write(f"\n  {'#':>2}  {'type':<28} {'start (bytes)':>15} "
              f"{'start LBA':>12} {'size':>12}  name\n")
    for p in parts:
        out.write(f"  {p.index:>2}  {p.type_label[:28]:<28} "
                  f"{p.start_offset:>15} {p.start_lba:>12} "
                  f"{_si(p.length):>12}  {p.name}\n")
    return out.getvalue()


def html_report(img: Image, scheme: str, parts: list[Partition],
                meta: dict | None, source: str) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{p.index}</td><td>{e(p.type_label)}</td>"
        f"<td class=m>{e(p.type_code)}</td><td class=n>{p.start_offset}</td>"
        f"<td class=n>{p.start_lba}</td><td class=n>{_si(p.length)}</td>"
        f"<td>{e(p.name)}</td><td>{'boot' if p.bootable else ''}</td></tr>"
        for p in parts)
    metarows = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>"
                       for k, v in (meta or {}).items())
    return f"""<!doctype html><meta charset=utf-8>
<title>mounting_image - {e(source)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111;background:#fff}}
 h1{{font-size:1.2rem}} table{{border-collapse:collapse;margin:1rem 0}}
 td,th{{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}}
 .n{{text-align:right;font-variant-numeric:tabular-nums}}
 .m{{font-family:ui-monospace,monospace;font-size:.85em}}
 caption{{text-align:left;font-weight:bold;margin-bottom:.3rem}}
 @media(prefers-color-scheme:dark){{body{{background:#111;color:#eee}}
  td,th{{border-color:#444}}}}
</style>
<h1>{e(source)}</h1>
<table><caption>Container</caption>
<tr><th>format</th><td>{e(img.format_name)}"""\
        f"{' / ' + e(img.subtype) if getattr(img, 'subtype', '') else ''}</td></tr>"\
        f"<tr><th>logical size</th><td>{img.size} bytes ({_si(img.size)})</td></tr>"\
        f"<tr><th>sector size</th><td>{img.sector_size}</td></tr>{metarows}</table>"\
        f"<table><caption>Partitions ({e(scheme)})</caption>"\
        f"<tr><th>#</th><th>type</th><th>type code</th><th>start (bytes)</th>"\
        f"<th>start LBA</th><th>size</th><th>name</th><th></th></tr>{rows}</table>"
