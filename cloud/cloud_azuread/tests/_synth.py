"""Build synthetic Entra ID sign-in / audit log exports matching the
real Microsoft Graph schema."""

from __future__ import annotations

import json
from pathlib import Path


def signin_record(*, user="alice@contoso.com", app="Office 365",
                  client_app="Browser", country="US", city="Seattle",
                  error_code=0, risk_state="none",
                  ca_status="success", when="2026-01-01T00:00:00Z",
                  ip="203.0.113.5"):
    return {
        "id": "signin-1", "createdDateTime": when, "userPrincipalName":
        user, "userDisplayName": user.split("@")[0], "appDisplayName": app,
        "ipAddress": ip, "clientAppUsed": client_app, "isInteractive": True,
        "conditionalAccessStatus": ca_status, "authenticationRequirement":
        "multiFactorAuthentication", "riskState": risk_state,
        "riskLevelAggregated": "none" if risk_state == "none" else "medium",
        "status": {"errorCode": error_code, "failureReason":
                  "" if error_code == 0 else "Invalid credentials"},
        "location": {"city": city, "countryOrRegion": country},
    }


def audit_record(*, activity="Add member to role", result="success",
                 actor="admin@contoso.com", target="Global Administrator",
                 when="2026-01-01T00:10:00Z"):
    return {
        "id": "audit-1", "activityDateTime": when, "activityDisplayName":
        activity, "category": "RoleManagement", "result": result,
        "resultReason": "", "initiatedBy": {"user": {"userPrincipalName":
                                                      actor, "ipAddress":
                                                      "203.0.113.5"}},
        "targetResources": [{"displayName": target, "type": "Role"}],
    }


def write_export(path: Path, records: list[dict], *, wrapped: bool = True
                 ) -> None:
    payload = {"value": records} if wrapped else records
    path.write_text(json.dumps(payload), encoding="utf-8")
