"""Per-record and cross-record notability heuristics."""

from __future__ import annotations

_INBOX_RULE_OPS = {"new-inboxrule", "set-inboxrule",
                   "new-transportrule", "set-transportrule"}
_FORWARD_PARAM_NAMES = ("forwardto", "redirectto", "forwardasattachmentto")
_CONSENT_OPS = {"consent to application"}
_ROLE_OPS = {"add member to role", "add member to group"}
_MAILBOX_PERM_OPS = {"add-mailboxpermission", "add-recipientpermission",
                     "add-mailboxfolderpermission"}
_DOWNLOAD_OPS = {"filedownloaded", "filesyncdownloadedfull"}


def _forwards_or_deletes(record: dict) -> bool:
    params = record.get("Parameters")
    if not isinstance(params, list):
        return False
    for p in params:
        if not isinstance(p, dict):
            continue
        name = str(p.get("Name", "")).lower()
        value = str(p.get("Value", "")).lower()
        if name in _FORWARD_PARAM_NAMES and value not in ("", "false"):
            return True
        if name == "deletemessage" and value == "true":
            return True
    return False


def flag_record(row: dict, record: dict) -> str:
    tags = []
    op = str(row["operation"]).lower()
    if op in _INBOX_RULE_OPS and _forwards_or_deletes(record):
        tags.append("mail-forwarding-rule")
    if op in _CONSENT_OPS:
        tags.append("app-consent")
    if op in _ROLE_OPS:
        tags.append("role-grant")
    if op in _MAILBOX_PERM_OPS:
        tags.append("mailbox-permission-change")
    if str(row["result"]).lower() == "failed":
        tags.append("operation-failed")
    return "+".join(tags)


def flag_mass_download(rows: list[dict], *, threshold: int = 10,
                       window_seconds: int = 300) -> None:
    """Mutate `rows` in place: flag a user whose file-download operations
    cluster >= threshold within a rolling window_seconds."""
    from datetime import datetime

    def parse(t):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(t, fmt)
            except (ValueError, TypeError):
                continue
        return None

    by_user: dict[str, list[dict]] = {}
    for r in rows:
        if str(r["operation"]).lower() not in _DOWNLOAD_OPS:
            continue
        by_user.setdefault(r["user"] or "?", []).append(r)

    for user, events in by_user.items():
        timed = [(parse(r["time"]), r) for r in events]
        timed = [(t, r) for t, r in timed if t is not None]
        timed.sort(key=lambda tr: tr[0])
        for i in range(len(timed)):
            start = timed[i][0]
            window = [r for t, r in timed[i:]
                     if (t - start).total_seconds() <= window_seconds]
            if len(window) >= threshold:
                for r in window:
                    if "mass-download" not in r["notable"]:
                        r["notable"] = (r["notable"] + "+mass-download"
                                       if r["notable"] else "mass-download")
                break
