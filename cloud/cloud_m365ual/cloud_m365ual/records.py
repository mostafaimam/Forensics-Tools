"""Read raw UAL records out of a CSV or JSON export file, parsing the
nested AuditData JSON string."""

from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path


def _parse_audit_data(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return {}


def _merge(outer: dict, inner: dict) -> dict:
    merged = dict(inner)
    for k, v in outer.items():
        if k == "AuditData":
            continue
        merged.setdefault(k, v)
    return merged


def _open_text(path: Path) -> str:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8-sig", "replace")


def _read_json(path: Path):
    text = _open_text(path).strip()
    if not text:
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                outer = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield _merge(outer, _parse_audit_data(outer.get("AuditData")))
        return
    records = obj.get("value") if isinstance(obj, dict) else obj
    if not isinstance(records, list):
        records = [obj]
    for outer in records:
        if not isinstance(outer, dict):
            continue
        yield _merge(outer, _parse_audit_data(outer.get("AuditData")))


def _read_csv(path: Path):
    text = _open_text(path)
    reader = csv.DictReader(text.splitlines())
    for outer in reader:
        yield _merge(outer, _parse_audit_data(outer.get("AuditData")))


def read_records(path: Path):
    name = path.name.lower()
    if name.endswith(".csv") or name.endswith(".csv.gz"):
        yield from _read_csv(path)
    else:
        yield from _read_json(path)
