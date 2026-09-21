"""Per-record and cross-record notability heuristics."""

from __future__ import annotations

_LEGACY_MARKERS = ("imap", "pop", "smtp", "activesync", "other clients",
                   "mapi")

_SENSITIVE_AUDIT_ACTIVITIES = {
    "add member to role", "add app role assignment to service principal",
    "consent to application", "add service principal",
    "update conditional access policy", "disable strong authentication",
    "delete user", "reset user password", "add owner to application",
    "update application - certificates and secrets management",
    "add app role assignment grant to user",
}


def _is_legacy_auth(client_app: str) -> bool:
    low = client_app.lower()
    return any(m in low for m in _LEGACY_MARKERS)


def flag_signin(row: dict) -> str:
    tags = []
    if row["result"] == "failure":
        tags.append("signin-failure")
    if _is_legacy_auth(row["client_app"]):
        tags.append("legacy-auth")
    if row["risk_state"] and row["risk_state"].lower() not in (
            "none", "dismissed", "remediated", ""):
        tags.append("risky-signin")
    if row["conditional_access_status"] == "failure":
        tags.append("ca-failure")
    return "+".join(tags)


def flag_audit(row: dict) -> str:
    if row["activity"].strip().lower() in _SENSITIVE_AUDIT_ACTIVITIES:
        return "sensitive-activity"
    return ""


def flag_new_country(rows: list[dict]) -> None:
    """Mutate `rows` in place: flag a sign-in from a country the same
    user has not been seen signing in from before (in event-time order)."""
    seen: dict[str, set[str]] = {}
    timed = [(r.get("time", ""), r) for r in rows if r["kind"] == "signin"
            and r.get("country")]
    timed.sort(key=lambda tr: tr[0])
    for _t, r in timed:
        user = r["actor"]
        countries = seen.setdefault(user, set())
        if countries and r["country"] not in countries:
            r["notable"] = (r["notable"] + "+new-country" if r["notable"]
                            else "new-country")
        countries.add(r["country"])
