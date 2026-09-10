"""Load IOC feeds, a geo table and a known-hash list."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path

# coarse first-octet -> RIR region (public IPv4 only; documentation only)
_RIR = {
    "ARIN (North America)": [(3, 3), (4, 4), (6, 9), (11, 24), (26, 26),
                             (28, 30), (32, 40), (44, 45), (47, 76),
                             (96, 100), (104, 108), (128, 174), (184, 216)],
    "RIPE NCC (Europe / ME)": [(2, 2), (5, 5), (25, 25), (31, 31), (37, 37),
                               (46, 46), (51, 51), (62, 62), (77, 95),
                               (109, 109), (141, 141), (145, 145),
                               (176, 176), (178, 178), (185, 185),
                               (188, 188), (193, 195), (212, 213), (217, 217)],
    "APNIC (Asia / Pacific)": [(1, 1), (14, 14), (27, 27), (36, 36), (39, 39),
                               (42, 43), (49, 49), (58, 61), (101, 103),
                               (110, 126), (150, 153), (163, 163), (171, 171),
                               (175, 175), (180, 183), (202, 203), (210, 211),
                               (218, 223)],
    "LACNIC (Latin America)": [(177, 177), (179, 179), (181, 181), (186, 187),
                               (189, 191), (200, 201)],
    "AFRINIC (Africa)": [(41, 41), (102, 102), (105, 105), (154, 156),
                         (196, 197)],
}


def region_for_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.version != 4 or not addr.is_global:
        return "private / reserved" if not addr.is_global else "IPv6"
    first = int(str(addr).split(".")[0])
    for region, ranges in _RIR.items():
        for lo, hi in ranges:
            if lo <= first <= hi:
                return region
    return "unallocated / other"


def load_geo_csv(path: str):
    nets = []
    for row in csv.reader(Path(path).read_text(encoding="utf-8-sig",
                                               errors="replace").splitlines()):
        if len(row) < 2:
            continue
        try:
            nets.append((ipaddress.ip_network(row[0].strip(), strict=False),
                         row[1].strip()))
        except ValueError:
            continue
    return nets


def geo_lookup(nets, ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, label in nets:
        if addr in net:
            return label
    return ""


_STIX_PAT = re.compile(r"value\s*=\s*'([^']+)'")


def load_feed(path: str) -> dict[str, str]:
    """Return {indicator_lower: source_label}."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    label = p.stem
    out: dict[str, str] = {}
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            items = data.get("indicators", data) if isinstance(data, dict) \
                else data
            for it in items if isinstance(items, list) else []:
                if isinstance(it, str):
                    out[it.lower()] = label
                elif isinstance(it, dict):
                    if it.get("pattern"):
                        for m in _STIX_PAT.finditer(it["pattern"]):
                            out[m.group(1).lower()] = it.get("name", label)
                    for k in ("value", "indicator", "ioc", "observable"):
                        if it.get(k):
                            out[str(it[k]).lower()] = it.get("source", label)
            return out
    # CSV or plain list
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if not row:
            continue
        val = row[0].strip().strip("\"'")
        if not val or val.startswith("#"):
            continue
        src = row[2].strip() if len(row) > 2 and row[2].strip() else label
        out[val.lower()] = src
    return out


def load_known(path: str) -> dict[str, str]:
    """Return {hash_lower: 'good'|'bad'|<label>}."""
    out: dict[str, str] = {}
    for row in csv.reader(Path(path).read_text(
            encoding="utf-8-sig", errors="replace").splitlines()):
        if len(row) < 2 or not re.fullmatch(r"[0-9a-fA-F]{32,64}",
                                            row[0].strip()):
            continue
        out[row[0].strip().lower()] = row[1].strip().lower()
    return out
