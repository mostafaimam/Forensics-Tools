"""Acquisition log (text), JSON manifest, and HTML report."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from pathlib import Path


def _si(n) -> str:
    f = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or u == "TiB":
            return f"{f:.2f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def text_log(res, meta: dict) -> str:
    L = []
    L.append("acquisition_image - acquisition log")
    L.append("=" * 40)
    for k in ("case_number", "evidence_number", "examiner", "description",
              "notes"):
        if meta.get(k):
            L.append(f"{k.replace('_', ' ').title():<18}: {meta[k]}")
    L.append("")
    L.append(f"Source            : {res.source}")
    L.append(f"Output            : {res.output}")
    L.append(f"Format            : {res.fmt}")
    L.append(f"Sector size       : {res.sector_size}")
    L.append(f"Bytes acquired    : {res.bytes_read} ({_si(res.bytes_read)})")
    L.append(f"Started (UTC)     : {res.started}")
    L.append(f"Finished (UTC)    : {res.finished}")
    L.append(f"Duration          : {res.seconds} s")
    if res.seconds:
        L.append(f"Average rate      : {_si(res.bytes_read / res.seconds)}/s")
    L.append("")
    L.append("Acquisition hashes")
    for a in ("md5", "sha1", "sha256"):
        if res.hashes.get(a):
            L.append(f"  {a.upper():<7}: {res.hashes[a]}")
    if res.verify_hashes:
        L.append("")
        L.append(f"Verification ({res.verified})")
        for a in ("md5", "sha1", "sha256"):
            if res.verify_hashes.get(a):
                mark = "OK" if res.verify_hashes[a] == res.hashes.get(a) else \
                    "MISMATCH"
                L.append(f"  {a.upper():<7}: {res.verify_hashes[a]}  [{mark}]")
    if res.bad_ranges:
        L.append("")
        L.append(f"Bad regions (zero-filled): {len(res.bad_ranges)}")
        for b in res.bad_ranges[:50]:
            L.append(f"  offset {b['offset']}  length {b['length']}")
    else:
        L.append("")
        L.append("Bad regions       : none")
    if len(res.segments) > 1:
        L.append("")
        L.append("Segments:")
        for s in res.segments:
            L.append(f"  {s}")
    return "\n".join(L) + "\n"


def manifest(res, meta: dict) -> str:
    d = asdict(res)
    d["metadata"] = meta
    d["tool"] = "acquisition_image"
    return json.dumps(d, indent=2, default=str)


def html_report(res, meta: dict) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><th>{e(k.replace('_',' ').title())}</th><td>{e(str(v))}</td></tr>"
        for k, v in meta.items() if v)
    hh = "".join(
        f"<tr><td>{a.upper()}</td><td class=m>{res.hashes.get(a,'')}</td>"
        f"<td class=m>{res.verify_hashes.get(a,'')}</td>"
        f"<td>{'✓' if res.verify_hashes.get(a)==res.hashes.get(a) and res.hashes.get(a) else ('✗' if res.verify_hashes else '')}</td></tr>"
        for a in ("md5", "sha1", "sha256"))
    bad = ("<p>Bad regions: none</p>" if not res.bad_ranges else
           "<p><b>Bad regions (zero-filled): "
           f"{len(res.bad_ranges)}</b></p><ul>" +
           "".join(f"<li>offset {b['offset']}, length {b['length']}</li>"
                   for b in res.bad_ranges[:100]) + "</ul>")
    return f"""<!doctype html><meta charset=utf-8>
<title>acquisition_image - {e(Path(res.output).name)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111;background:#fff}}
 h1{{font-size:1.2rem}} table{{border-collapse:collapse;margin:1rem 0}}
 td,th{{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}}
 .m{{font-family:ui-monospace,monospace;font-size:.85em}}
 .ok{{color:#177245;font-weight:bold}} .bad{{color:#b00;font-weight:bold}}
 @media(prefers-color-scheme:dark){{body{{background:#111;color:#eee}}
  td,th{{border-color:#444}}}}
</style>
<h1>Acquisition &mdash; {e(Path(res.output).name)}</h1>
<p class="{ 'ok' if res.ok else 'bad' }">
  {'VERIFIED &amp; COMPLETE' if res.ok and res.verified=='ok'
   else ('COMPLETE (not verified)' if res.ok else 'REVIEW - see below')}</p>
<table><caption>Case</caption>{rows}</table>
<table><caption>Acquisition</caption>
<tr><th>source</th><td>{e(res.source)}</td></tr>
<tr><th>output</th><td>{e(res.output)}</td></tr>
<tr><th>format</th><td>{e(res.fmt)}</td></tr>
<tr><th>bytes</th><td>{res.bytes_read} ({_si(res.bytes_read)})</td></tr>
<tr><th>started</th><td>{e(res.started)}</td></tr>
<tr><th>finished</th><td>{e(res.finished)}</td></tr>
<tr><th>duration</th><td>{res.seconds} s</td></tr>
</table>
<table><caption>Hashes</caption>
<tr><th>algo</th><th>acquisition</th><th>verification</th><th></th></tr>{hh}</table>
{bad}
"""
