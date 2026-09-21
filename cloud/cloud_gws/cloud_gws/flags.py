"""Per-event notability heuristics.

Match on substrings of the application/event name/parameters rather
than exact enum strings where reasonable - Workspace's exact event and
parameter names vary somewhat across audit categories and this
project's confidence in every precise string is lower than in the
overall envelope shape (see the README).
"""

from __future__ import annotations


def flag_event(row: dict) -> str:
    app = row["application"].lower()
    name = row["event_name"].lower()
    params = row["parameters"].lower()
    tags = []

    if app == "login" and "failure" in name:
        tags.append("login-failure")
    if "suspicious" in name or "is_suspicious=true" in params:
        tags.append("suspicious-login")
    if app == "admin" and any(k in name for k in
                              ("role", "privilege", "delegated_admin")):
        tags.append("admin-role-change")
    if app == "token" and "authorize" in name:
        tags.append("oauth-grant")
    if app == "drive" and any(k in name for k in
                              ("share", "visibility", "acl_change",
                               "change_user_access")):
        if any(k in params for k in ("outside", "external", "anyone",
                                     "public")):
            tags.append("external-sharing")
    if app == "login" and any(k in name for k in
                              ("2sv_disable", "two_step_disable")):
        tags.append("2sv-disabled")
    return "+".join(tags)
