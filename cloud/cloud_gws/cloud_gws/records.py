"""Read raw Reports API activity records out of an export file."""

from __future__ import annotations

import gzip
import json
from pathlib import Path


def _open_text(path: Path) -> str:
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8-sig", "replace")


def read_activities(path: Path):
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
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        return
    if isinstance(obj, dict) and isinstance(obj.get("items"), list):
        yield from obj["items"]
    elif isinstance(obj, list):
        yield from obj
    elif isinstance(obj, dict):
        yield obj
