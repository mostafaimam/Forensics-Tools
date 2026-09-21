"""Build synthetic Reports API activity exports matching the real schema."""

from __future__ import annotations

import json
from pathlib import Path


def activity(*, application="login", event_name="login_success",
            event_type="login", actor_email="alice@example.com",
            ip="203.0.113.5", when="2026-01-01T00:00:00.000Z",
            parameters=None):
    return {
        "kind": "admin#reports#activity",
        "id": {"time": when, "uniqueQualifier": "1", "applicationName":
              application, "customerId": "C123"},
        "actor": {"email": actor_email, "profileId": "p1"},
        "ipAddress": ip,
        "events": [{"type": event_type, "name": event_name,
                   "parameters": parameters or []}],
    }


def login_failure(when="2026-01-01T00:00:00.000Z"):
    return activity(application="login", event_name="login_failure",
                    parameters=[{"name": "login_type", "value":
                                "google_password"}], when=when)


def suspicious_login(when="2026-01-01T00:01:00.000Z"):
    return activity(application="login", event_name="login_success",
                    parameters=[{"name": "is_suspicious",
                                "boolValue": True}], when=when)


def admin_role_change(when="2026-01-01T00:02:00.000Z"):
    return activity(application="admin", event_type="DELEGATED_ADMIN_SETTINGS",
                    event_name="ASSIGN_ROLE",
                    parameters=[{"name": "USER_EMAIL", "value":
                                "bob@example.com"}], when=when)


def oauth_grant(when="2026-01-01T00:03:00.000Z"):
    return activity(application="token", event_type="authorize",
                    event_name="authorize",
                    parameters=[{"name": "client_id", "value":
                                "12345.apps.googleusercontent.com"},
                               {"name": "app_name", "value": "Evil App"}],
                    when=when)


def external_sharing(when="2026-01-01T00:04:00.000Z"):
    return activity(application="drive", event_type="acl_change",
                    event_name="change_document_visibility",
                    parameters=[{"name": "doc_title", "value":
                                "secret-plans.docx"},
                               {"name": "visibility", "value":
                                "shared_externally: outside domain"}],
                    when=when)


def benign_drive_view(when="2026-01-01T00:05:00.000Z"):
    return activity(application="drive", event_type="access",
                    event_name="view",
                    parameters=[{"name": "doc_title", "value":
                                "notes.docx"}], when=when)


def write_export(path: Path, activities: list[dict]) -> None:
    path.write_text(json.dumps({"kind": "admin#reports#activities",
                               "items": activities}), encoding="utf-8")
