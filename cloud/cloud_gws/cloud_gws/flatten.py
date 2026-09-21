"""Expand one Reports API activity record into one row per event."""

from __future__ import annotations

COLUMNS = ["time", "application", "actor_email", "ip", "event_type",
          "event_name", "target", "parameters", "notable", "source"]

_TARGET_PARAM_NAMES = ("doc_title", "target_user", "USER_EMAIL",
                       "group_email", "app_name", "client_id",
                       "old_value", "new_value")


def _flatten_params(params: list) -> tuple[str, str]:
    """Return (summary_string, target_guess)."""
    parts = []
    target = ""
    for p in params or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        name = p["name"]
        value = p.get("value")
        if value is None:
            if "boolValue" in p:
                value = p["boolValue"]
            elif "multiValue" in p:
                value = ",".join(str(v) for v in p["multiValue"])
            elif "intValue" in p:
                value = p["intValue"]
        parts.append(f"{name}={value}")
        if not target and name in _TARGET_PARAM_NAMES and value:
            target = str(value)
    return "; ".join(parts), target


def flatten_activity(activity: dict, source: str) -> list[dict]:
    ident = activity.get("id") or {}
    actor = activity.get("actor") or {}
    time = ident.get("time", "")
    application = ident.get("applicationName", "")
    actor_email = actor.get("email", "") or actor.get("key", "")
    ip = activity.get("ipAddress", "")

    rows = []
    for event in activity.get("events") or []:
        if not isinstance(event, dict):
            continue
        params_str, target = _flatten_params(event.get("parameters"))
        rows.append({
            "time": time, "application": application,
            "actor_email": actor_email, "ip": ip,
            "event_type": event.get("type", ""),
            "event_name": event.get("name", ""),
            "target": target, "parameters": params_str,
            "notable": "", "source": source,
        })
    return rows
