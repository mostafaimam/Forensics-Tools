"""Load a tabular file (CSV / TSV / JSON / JSONL / XLSX) to rows + columns."""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

_XL_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


class ReadError(Exception):
    pass


def _sniff_delim(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t;|").delimiter
    except csv.Error:
        counts = {d: sample.count(d) for d in ",\t;|"}
        return max(counts, key=counts.get) if any(counts.values()) else ","


def read_csv(path: Path, delim: str | None = None) -> tuple[list[dict], list[str]]:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("latin-1", "replace")
    d = delim or _sniff_delim(text[:8192])
    rdr = csv.reader(io.StringIO(text), delimiter=d)
    rows_raw = list(rdr)
    if not rows_raw:
        return [], []
    header = [h.strip() or f"col{i}" for i, h in enumerate(rows_raw[0])]
    header = _dedupe(header)
    out = []
    for r in rows_raw[1:]:
        if not any(c.strip() for c in r):
            continue
        rec = {header[i]: (r[i] if i < len(r) else "")
               for i in range(len(header))}
        out.append(rec)
    return out, header


def read_json(path: Path) -> tuple[list[dict], list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    records: list[dict] = []
    if text[:1] == "[":
        data = json.loads(text)
        records = [r for r in data if isinstance(r, dict)]
    else:                                        # JSONL
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    cols: list[str] = []
    for r in records:
        for k in r:
            if k not in cols:
                cols.append(k)
    flat = [{k: _flat(rec.get(k, "")) for k in cols} for rec in records]
    return flat, cols


def _col_ref_to_idx(ref: str) -> int:
    m = re.match(r"([A-Z]+)", ref)
    letters = m.group(1) if m else "A"
    n = 0
    for c in letters:
        n = n * 26 + (ord(c) - 64)
    return n - 1


def read_xlsx(path: Path, sheet: str | None = None) -> tuple[list[dict],
                                                             list[str]]:
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise ReadError(f"not a valid xlsx: {e}")
    shared: list[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
        for si in root.findall(f"{_XL_NS}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{_XL_NS}t")))
    sheets = sorted(n for n in zf.namelist()
                    if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
    if not sheets:
        raise ReadError("xlsx has no worksheets")
    target = sheets[0]
    if sheet:
        for s in sheets:
            if sheet.lower() in s.lower():
                target = s
                break
    root = ET.fromstring(zf.read(target))
    grid: list[list[str]] = []
    for row in root.iter(f"{_XL_NS}row"):
        cells: dict[int, str] = {}
        for c in row.findall(f"{_XL_NS}c"):
            ref = c.get("r", "A1")
            idx = _col_ref_to_idx(ref)
            t = c.get("t")
            v = c.find(f"{_XL_NS}v")
            val = ""
            if t == "s" and v is not None:
                si = int(v.text)
                val = shared[si] if si < len(shared) else ""
            elif t == "inlineStr":
                isn = c.find(f"{_XL_NS}is")
                val = "".join(x.text or "" for x in isn.iter(f"{_XL_NS}t")) \
                    if isn is not None else ""
            elif v is not None:
                val = v.text or ""
            cells[idx] = val
        width = (max(cells) + 1) if cells else 0
        grid.append([cells.get(i, "") for i in range(width)])
    if not grid:
        return [], []
    hdr = _dedupe([h.strip() or f"col{i}" for i, h in enumerate(grid[0])])
    out = []
    for r in grid[1:]:
        if not any(str(c).strip() for c in r):
            continue
        out.append({hdr[i]: (r[i] if i < len(r) else "")
                    for i in range(len(hdr))})
    return out, hdr


def _dedupe(cols: list[str]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for c in cols:
        if c in seen:
            seen[c] += 1
            out.append(f"{c}_{seen[c]}")
        else:
            seen[c] = 0
            out.append(c)
    return out


def _flat(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, default=str)[:2000]
    if v is None:
        return ""
    return str(v)


def load(path: str | Path, *, delim: str | None = None,
         sheet: str | None = None) -> tuple[list[dict], list[str]]:
    p = Path(path)
    suf = p.suffix.lower()
    if suf == ".xlsx":
        return read_xlsx(p, sheet)
    if suf in (".json", ".jsonl", ".ndjson"):
        return read_json(p)
    if suf in (".tsv",):
        return read_csv(p, delim or "\t")
    return read_csv(p, delim)
