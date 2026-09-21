"""Build synthetic Unified Audit Log exports matching the real schema."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _audit_data(*, record_id="rec-1", when="2026-01-01T00:00:00Z",
                operation="FileAccessed", workload="SharePoint",
                user="alice@contoso.com", client_ip="203.0.113.5",
                object_id="https://contoso.sharepoint.com/doc.docx",
                result="Succeeded", record_type=6, parameters=None):
    d = {
        "Id": record_id, "CreationTime": when, "Operation": operation,
        "Workload": workload, "UserId": user, "ClientIP": client_ip,
        "ObjectId": object_id, "ResultStatus": result, "RecordType":
        record_type,
    }
    if parameters is not None:
        d["Parameters"] = parameters
    return d


def outer_record(**kwargs):
    audit = _audit_data(**kwargs)
    return {
        "RecordId": audit["Id"], "CreationDate": audit["CreationTime"],
        "UserIds": audit["UserId"], "Operations": audit["Operation"],
        "RecordType": audit["RecordType"],
        "AuditData": json.dumps(audit),
    }


def write_json_export(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps(records), encoding="utf-8")


def write_csv_export(path: Path, records: list[dict]) -> None:
    fieldnames = ["RecordId", "CreationDate", "UserIds", "Operations",
                 "AuditData", "RecordType"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in records:
            w.writerow(r)


def mail_forwarding_rule_record(when="2026-01-01T00:00:00Z"):
    return outer_record(
        operation="New-InboxRule", workload="Exchange",
        object_id="Inbox Rule", when=when,
        parameters=[{"Name": "ForwardTo", "Value": "attacker@evil.example"},
                   {"Name": "Name", "Value": "Auto-forward"}])


def benign_inbox_rule_record(when="2026-01-01T00:01:00Z"):
    return outer_record(
        operation="New-InboxRule", workload="Exchange",
        object_id="Inbox Rule", when=when,
        parameters=[{"Name": "MoveToFolder", "Value": "Archive"}])


def consent_record(when="2026-01-01T00:02:00Z"):
    return outer_record(operation="Consent to application",
                        workload="AzureActiveDirectory", when=when)


def role_grant_record(when="2026-01-01T00:03:00Z"):
    return outer_record(operation="Add member to role",
                        workload="AzureActiveDirectory", when=when)


def mailbox_permission_record(when="2026-01-01T00:04:00Z"):
    return outer_record(operation="Add-MailboxPermission",
                        workload="Exchange", when=when)


def failed_record(when="2026-01-01T00:05:00Z"):
    return outer_record(operation="FileAccessed", result="Failed",
                        when=when)


def download_burst_records(n=12, user="bob@contoso.com",
                           when_start="2026-01-01T01:00:00Z"):
    from datetime import datetime, timedelta
    base = datetime.strptime(when_start, "%Y-%m-%dT%H:%M:%SZ")
    out = []
    for i in range(n):
        t = (base + timedelta(seconds=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out.append(outer_record(operation="FileDownloaded", user=user,
                                when=t, object_id=f"doc{i}.docx"))
    return out
