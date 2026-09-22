"""Flatten a decoded plist value or a protobuf field list into rows."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from mobile_appcommon.protobuf import Field


def _scalar(v) -> str:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(v, (bytes, bytearray)):
        if len(v) <= 64:
            return "base64:" + base64.b64encode(v).decode()
        return (f"<{len(v)} bytes> base64:" +
               base64.b64encode(v[:48]).decode() + "...")
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def flatten_plist(value, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(value, dict):
        if not value:
            out[prefix or "."] = "{}"
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten_plist(v, key))
    elif isinstance(value, (list, tuple)):
        if not value:
            out[prefix or "."] = "[]"
        for i, v in enumerate(value):
            out.update(flatten_plist(v, f"{prefix}[{i}]"))
    elif value is None:
        out[prefix or "."] = ""
    else:
        out[prefix or "."] = _scalar(value)
    return out


def flatten_protobuf(fields: list[Field], prefix: str = "") -> list[dict]:
    rows = []
    for f in fields:
        path = f"{prefix}.{f.number}" if prefix else str(f.number)
        if f.kind == "message":
            rows.append({"path": path, "wire_type": f.wire_type,
                        "kind": f.kind,
                        "value": f"<{len(f.value)} nested field(s)>"})
            rows.extend(flatten_protobuf(f.value, path))
        else:
            rows.append({"path": path, "wire_type": f.wire_type,
                        "kind": f.kind, "value": _scalar(f.value)})
    return rows
