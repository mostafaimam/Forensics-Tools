"""Flatten sign-in and directory-audit records into one unified schema."""

from __future__ import annotations

COLUMNS = ["kind", "time", "actor", "app", "activity", "result", "ip",
          "country", "city", "client_app", "is_interactive",
          "conditional_access_status", "authentication_requirement",
          "risk_state", "risk_level", "error_code", "error_detail",
          "targets", "notable", "source"]


def _get(d, *path, default=""):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def flatten_signin(record: dict, source: str) -> dict:
    status = record.get("status") or {}
    location = record.get("location") or {}
    return {
        "kind": "signin",
        "time": record.get("createdDateTime", ""),
        "actor": record.get("userPrincipalName", ""),
        "app": record.get("appDisplayName", ""),
        "activity": "SignIn",
        "result": "success" if not status.get("errorCode") else "failure",
        "ip": record.get("ipAddress", ""),
        "country": location.get("countryOrRegion", ""),
        "city": location.get("city", ""),
        "client_app": record.get("clientAppUsed", ""),
        "is_interactive": record.get("isInteractive", ""),
        "conditional_access_status": record.get("conditionalAccessStatus",
                                                 ""),
        "authentication_requirement": record.get(
            "authenticationRequirement", ""),
        "risk_state": record.get("riskState", ""),
        "risk_level": record.get("riskLevelAggregated", ""),
        "error_code": status.get("errorCode", ""),
        "error_detail": status.get("failureReason", ""),
        "targets": "",
        "notable": "",
        "source": source,
    }


def flatten_audit(record: dict, source: str) -> dict:
    initiated_by = record.get("initiatedBy") or {}
    actor = _get(initiated_by, "user", "userPrincipalName") or \
        _get(initiated_by, "app", "displayName")
    targets = record.get("targetResources") or []
    target_names = ", ".join(
        t.get("displayName", "") for t in targets if isinstance(t, dict)
        and t.get("displayName"))
    return {
        "kind": "audit",
        "time": record.get("activityDateTime", ""),
        "actor": actor or "",
        "app": _get(initiated_by, "app", "displayName"),
        "activity": record.get("activityDisplayName", ""),
        "result": record.get("result", ""),
        "ip": _get(initiated_by, "user", "ipAddress"),
        "country": "",
        "city": "",
        "client_app": "",
        "is_interactive": "",
        "conditional_access_status": "",
        "authentication_requirement": "",
        "risk_state": "",
        "risk_level": "",
        "error_code": "",
        "error_detail": record.get("resultReason", ""),
        "targets": target_names,
        "notable": "",
        "source": source,
    }
