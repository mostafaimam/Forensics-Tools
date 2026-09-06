"""Acquisition log (text) and JSON manifest."""

from __future__ import annotations

import json
from dataclasses import asdict


def _si(n) -> str:
    f = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or u == "TiB":
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def text_log(res, meta: dict) -> str:
    L = ["acquisition_ram - acquisition log", "=" * 40]
    for k in ("case_number", "evidence_number", "examiner", "description",
              "notes"):
        if meta.get(k):
            L.append(f"{k.replace('_', ' ').title():<16}: {meta[k]}")
    L.append("")
    L.append(f"Method        : {res.method}")
    L.append(f"Host OS       : {res.host_os}")
    L.append(f"Started (UTC) : {res.started}")
    L.append(f"Finished (UTC): {res.finished}")
    L.append(f"Duration      : {res.seconds} s")
    if res.total_ram:
        L.append(f"Physical RAM  : {res.total_ram} ({_si(res.total_ram)})")
    if res.ranges:
        L.append(f"RAM ranges    : {len(res.ranges)}")
        for r in res.ranges[:32]:
            L.append(f"  {r['start']:#014x} - {r['end']:#014x}  "
                     f"({_si(r['end'] - r['start'])})")
    L.append("")
    L.append("Outputs")
    for o in res.outputs:
        L.append(f"  {o.name}"
                 + (f"  [{o.category}]" if o.category else "")
                 + f"  {_si(o.size)}")
        if o.path:
            L.append(f"    -> {o.path}")
        for a in ("sha256", "sha1", "md5"):
            if o.hashes.get(a):
                L.append(f"    {a.upper()}: {o.hashes[a]}")
        if o.note:
            L.append(f"    note: {o.note}")
    if res.warnings:
        L.append("")
        L.append("Warnings")
        for w in res.warnings:
            L.append(f"  - {w}")
    return "\n".join(L) + "\n"


def manifest(res, meta: dict) -> str:
    d = asdict(res)
    d["metadata"] = meta
    d["tool"] = "acquisition_ram"
    return json.dumps(d, indent=2, default=str)
