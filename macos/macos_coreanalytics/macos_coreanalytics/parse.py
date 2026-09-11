"""Load one .core_analytics file as a plist or NDJSON document."""

from __future__ import annotations

import json
import plistlib

from macos_coreanalytics.nskeyedarchiver import is_keyed_archive, unwrap


class ParseError(Exception):
    pass


def load_bytes(data: bytes):
    """Return (kind, document) where kind is 'plist' | 'ndjson'."""
    head = data[:8]
    if head.startswith(b"bplist00") or head.lstrip()[:5] == b"<?xml":
        try:
            doc = plistlib.loads(data)
        except Exception as e:  # noqa: BLE001
            raise ParseError(f"plist parse error: {e}") from e
        if is_keyed_archive(doc):
            doc = unwrap(doc)
        return "plist", doc

    text = data.decode("utf-8", "replace")
    objs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if objs:
        return "ndjson", objs

    # last resort: maybe it's one big JSON document, not line-delimited
    try:
        return "ndjson", [json.loads(text)]
    except json.JSONDecodeError as e:
        raise ParseError(f"neither a plist nor JSON: {e}") from e
