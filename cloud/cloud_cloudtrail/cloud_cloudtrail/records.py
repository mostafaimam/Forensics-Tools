"""Read raw CloudTrail records out of a delivery file."""

from __future__ import annotations

import gzip
import json
from pathlib import Path


def _open_text(path: Path) -> str:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8", "replace")


def read_records(path: Path):
    text = _open_text(path)
    text = text.strip()
    if not text:
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON fallback: one record per line
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        return
    if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        yield from obj["Records"]
    elif isinstance(obj, list):
        yield from obj
    elif isinstance(obj, dict):
        yield obj
