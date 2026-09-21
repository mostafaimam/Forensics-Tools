"""Per-record and cross-record notability heuristics."""

from __future__ import annotations

_IAM_PREFIXES = ("Create", "Delete", "Put", "Attach", "Detach", "Update",
                 "Add", "Remove")
_SECRET_ACTIONS = {"GetSecretValue", "GetParameter", "GetParameters",
                  "GetParametersByPath", "DecryptSecret"}
_PUBLIC_GRANTEES = ("AllUsers", "AllAuthenticatedUsers",
                   "http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/"
                   "AllAuthenticatedUsers")


def _has_public_grant(record: dict) -> bool:
    params = record.get("requestParameters") or {}
    blob = str(params)
    return any(g in blob for g in _PUBLIC_GRANTEES)


def flag_record(row: dict, record: dict) -> str:
    tags = []
    if row["identity_type"] == "Root":
        tags.append("root-account-usage")
    if (row["event_source"] == "iam.amazonaws.com" and
            row["event_name"].startswith(_IAM_PREFIXES)):
        tags.append("iam-change")
    if row["event_name"] == "ConsoleLogin":
        success = _get_response(record, "ConsoleLogin") == "Success"
        if success and row["mfa_authenticated"].lower() != "true":
            tags.append("console-login-no-mfa")
    if row["event_name"] in _SECRET_ACTIONS:
        tags.append("secret-access")
    if row["event_name"] in ("PutBucketAcl", "PutObjectAcl",
                             "PutBucketPolicy") and _has_public_grant(record):
        tags.append("public-access-change")
    if row["error_code"] and "denied" in row["error_code"].lower():
        tags.append("access-denied")
    return "+".join(tags)


def _get_response(record: dict, key: str) -> str:
    resp = record.get("responseElements") or {}
    v = resp.get(key) if isinstance(resp, dict) else None
    return v or ""


def flag_delete_bursts(rows: list[dict], *, threshold: int = 5,
                       window_seconds: int = 300) -> None:
    """Mutate `rows` in place: append 'delete-burst' to notable for any
    actor whose Delete* actions cluster >= threshold within a rolling
    window_seconds."""
    from datetime import datetime

    def parse(t):
        try:
            return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            return None

    by_actor: dict[str, list[dict]] = {}
    for r in rows:
        if not r["event_name"].startswith("Delete"):
            continue
        actor = r["principal_arn"] or r["user_name"] or "?"
        by_actor.setdefault(actor, []).append(r)

    for actor, events in by_actor.items():
        timed = [(parse(r["event_time"]), r) for r in events]
        timed = [(t, r) for t, r in timed if t is not None]
        timed.sort(key=lambda tr: tr[0])
        for i in range(len(timed)):
            start = timed[i][0]
            window = [r for t, r in timed[i:]
                     if (t - start).total_seconds() <= window_seconds]
            if len(window) >= threshold:
                for r in window:
                    if "delete-burst" not in r["notable"]:
                        r["notable"] = (r["notable"] + "+delete-burst"
                                       if r["notable"] else "delete-burst")
                break
