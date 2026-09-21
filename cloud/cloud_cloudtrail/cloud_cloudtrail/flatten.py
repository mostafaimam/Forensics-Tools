"""Flatten one raw CloudTrail record into a normalised row."""

from __future__ import annotations

COLUMNS = ["event_time", "event_name", "event_source", "event_type",
          "aws_region", "source_ip", "user_agent", "identity_type",
          "principal_arn", "user_name", "account_id", "access_key_id",
          "mfa_authenticated", "assumed_role_arn", "read_only",
          "error_code", "error_message", "event_id", "request_id",
          "recipient_account_id", "notable", "source"]


def _get(d, *path, default=""):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def flatten(record: dict, source: str) -> dict:
    identity = record.get("userIdentity") or {}
    session_issuer = _get(identity, "sessionContext", "sessionIssuer",
                          default={})
    mfa = _get(identity, "sessionContext", "attributes",
              "mfaAuthenticated", default="")
    return {
        "event_time": record.get("eventTime", ""),
        "event_name": record.get("eventName", ""),
        "event_source": record.get("eventSource", ""),
        "event_type": record.get("eventType", ""),
        "aws_region": record.get("awsRegion", ""),
        "source_ip": record.get("sourceIPAddress", ""),
        "user_agent": record.get("userAgent", ""),
        "identity_type": identity.get("type", ""),
        "principal_arn": identity.get("arn", ""),
        "user_name": identity.get("userName", ""),
        "account_id": identity.get("accountId", ""),
        "access_key_id": identity.get("accessKeyId", ""),
        "mfa_authenticated": str(mfa),
        "assumed_role_arn": session_issuer.get("arn", "")
        if isinstance(session_issuer, dict) else "",
        "read_only": record.get("readOnly", ""),
        "error_code": record.get("errorCode", ""),
        "error_message": record.get("errorMessage", ""),
        "event_id": record.get("eventID", ""),
        "request_id": record.get("requestID", ""),
        "recipient_account_id": record.get("recipientAccountId", ""),
        "notable": "",
        "source": source,
    }
