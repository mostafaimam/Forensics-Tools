"""Carve JSON objects out of an arbitrary byte blob.

A LevelDB value is sometimes a bare JSON document and sometimes JSON
embedded in a larger structure; this scans for balanced ``{...}`` spans
(respecting string quoting/escapes) and tries to parse each one,
keeping only what actually decodes.
"""

from __future__ import annotations

import json


def _iter_balanced_spans(text: str):
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, c in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    yield text[start:i + 1]
                    start = -1


def find_json_objects(data: bytes, *, max_objects: int = 200) -> list[dict]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", "ignore")
    if "{" not in text:
        return []
    out = []
    for span in _iter_balanced_spans(text):
        try:
            obj = json.loads(span)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
            if len(out) >= max_objects:
                break
    return out
