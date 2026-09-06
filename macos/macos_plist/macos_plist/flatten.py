"""Flatten a nested plist value into dot / bracket paths for CSV output, and
normalise Apple types to strings."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from macos_plist.reader import cocoa_to_utc, looks_like_cocoa_time


def _scalar(v) -> str:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(v, (bytes, bytearray)):
        if len(v) <= 64:
            return "base64:" + base64.b64encode(v).decode()
        return f"<{len(v)} bytes> base64:" + base64.b64encode(v[:48]).decode() + "…"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and looks_like_cocoa_time(v):
        dt = cocoa_to_utc(v)
        return f"{v} (~{dt.strftime('%Y-%m-%dT%H:%M:%SZ')})" if dt else str(v)
    return str(v)


def flatten(value, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(value, dict):
        if not value:
            out[prefix or "."] = "{}"
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten(v, key))
    elif isinstance(value, (list, tuple)):
        if not value:
            out[prefix or "."] = "[]"
        for i, v in enumerate(value):
            out.update(flatten(v, f"{prefix}[{i}]"))
    elif value is None:
        out[prefix or "."] = ""
    else:
        out[prefix or "."] = _scalar(value)
    return out


def json_safe(value):
    """Recursively convert to JSON-serialisable types."""
    try:
        from plistlib import UID
    except ImportError:  # pragma: no cover
        UID = ()  # type: ignore
    if UID and isinstance(value, UID):
        return {"__CF$UID__": value.data}
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes_b64__": base64.b64encode(value).decode()}
    return value


def get_path(value, path: str):
    """Navigate an ``a.b[0].c`` style path.

    Dictionary keys may themselves contain dots (bundle identifiers are the
    common case): at each dict we take the longest key that matches a
    dot-delimited prefix of what's left of the path.
    """
    cur = value
    rest = path
    while rest:
        rest = rest.lstrip(".")
        if not rest:
            break
        if rest[0] == "[":
            end = rest.index("]")
            idx = int(rest[1:end])
            if not isinstance(cur, (list, tuple)) or idx >= len(cur):
                return None
            cur = cur[idx]
            rest = rest[end + 1:]
            continue
        # a dict segment: greedily match the longest key
        if not isinstance(cur, dict):
            return None
        chunk = rest.split("[", 1)[0]
        candidates = [k for k in chunk.split(".")]
        matched = None
        for i in range(len(candidates), 0, -1):
            key = ".".join(candidates[:i])
            if key in cur:
                matched = key
                break
        if matched is None:
            return None
        cur = cur[matched]
        rest = rest[len(matched):]
    return cur
