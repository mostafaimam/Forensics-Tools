"""Flatten one merged UAL record into a common activity row."""

from __future__ import annotations

COLUMNS = ["time", "workload", "record_type", "operation", "user",
          "client_ip", "object", "result", "details", "notable", "source"]


def _first(record: dict, *keys, default=""):
    for k in keys:
        v = record.get(k)
        if v not in (None, ""):
            return v
    return default


def _rule_details(record: dict) -> str:
    params = record.get("Parameters")
    if not isinstance(params, list):
        return ""
    parts = []
    for p in params:
        if isinstance(p, dict) and p.get("Name") and p.get("Value"):
            parts.append(f"{p['Name']}={p['Value']}")
    return "; ".join(parts)


def flatten(record: dict, source: str) -> dict:
    return {
        "time": _first(record, "CreationTime", "CreationDate"),
        "workload": _first(record, "Workload"),
        "record_type": str(_first(record, "RecordType")),
        "operation": _first(record, "Operation", "Operations"),
        "user": _first(record, "UserId", "UserIds", "UserKey"),
        "client_ip": _first(record, "ClientIP", "ClientIPAddress"),
        "object": _first(record, "ObjectId"),
        "result": _first(record, "ResultStatus", default="Succeeded"),
        "details": _rule_details(record),
        "notable": "",
        "source": source,
    }
