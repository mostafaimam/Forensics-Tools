"""Build synthetic CloudTrail delivery files matching the real schema."""

from __future__ import annotations

import gzip
import json
from pathlib import Path


def _iam_user(name="alice", account="111122223333"):
    return {
        "type": "IAMUser", "principalId": "AIDAEXAMPLE", "arn":
        f"arn:aws:iam::{account}:user/{name}", "accountId": account,
        "accessKeyId": "AKIAEXAMPLE", "userName": name,
    }


def console_login_record(*, mfa=False, success=True, when="2026-01-01T00:00:00Z"):
    return {
        "eventVersion": "1.08", "eventTime": when, "eventSource":
        "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion":
        "us-east-1", "sourceIPAddress": "203.0.113.5", "userAgent":
        "Mozilla/5.0", "userIdentity": _iam_user(),
        "responseElements": {"ConsoleLogin": "Success" if success
                             else "Failure"},
        "additionalEventData": {"MFAUsed": "Yes" if mfa else "No"},
        "eventID": "evt-login", "requestID": "req-login", "eventType":
        "AwsConsoleSignIn", "recipientAccountId": "111122223333",
    }


def iam_change_record(event_name="CreateUser", when="2026-01-01T00:01:00Z"):
    return {
        "eventVersion": "1.08", "eventTime": when, "eventSource":
        "iam.amazonaws.com", "eventName": event_name, "awsRegion":
        "us-east-1", "sourceIPAddress": "203.0.113.5", "userAgent": "aws-cli",
        "userIdentity": _iam_user(), "requestParameters": {"userName":
                                                            "newuser"},
        "responseElements": {}, "readOnly": False, "eventID":
        f"evt-{event_name}", "requestID": "req-iam", "eventType":
        "AwsApiCall", "recipientAccountId": "111122223333",
    }


def secret_access_record(when="2026-01-01T00:02:00Z"):
    return {
        "eventVersion": "1.08", "eventTime": when, "eventSource":
        "secretsmanager.amazonaws.com", "eventName": "GetSecretValue",
        "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.9",
        "userAgent": "boto3", "userIdentity": _iam_user("bob"),
        "requestParameters": {"secretId": "prod/db/password"},
        "readOnly": True, "eventID": "evt-secret", "requestID":
        "req-secret", "eventType": "AwsApiCall", "recipientAccountId":
        "111122223333",
    }


def public_acl_record(when="2026-01-01T00:03:00Z"):
    return {
        "eventVersion": "1.08", "eventTime": when, "eventSource":
        "s3.amazonaws.com", "eventName": "PutBucketAcl", "awsRegion":
        "us-east-1", "sourceIPAddress": "198.51.100.9", "userAgent":
        "aws-cli", "userIdentity": _iam_user("bob"),
        "requestParameters": {"bucketName": "example-bucket",
                              "AccessControlPolicy": {"AccessControlList":
                                                      {"Grant": [
                                                          {"Grantee": {
                                                              "URI":
                                                              "http://acs."
                                                              "amazonaws.com"
                                                              "/groups/"
                                                              "global/"
                                                              "AllUsers"},
                                                           "Permission":
                                                          "READ"}]}}},
        "readOnly": False, "eventID": "evt-acl", "requestID": "req-acl",
        "eventType": "AwsApiCall", "recipientAccountId": "111122223333",
    }


def root_usage_record(when="2026-01-01T00:04:00Z"):
    r = iam_change_record("DeleteUser", when)
    r["userIdentity"] = {"type": "Root", "principalId": "111122223333",
                        "arn": "arn:aws:iam::111122223333:root",
                        "accountId": "111122223333"}
    return r


def assumed_role_record(when="2026-01-01T00:05:00Z"):
    return {
        "eventVersion": "1.08", "eventTime": when, "eventSource":
        "ec2.amazonaws.com", "eventName": "RunInstances", "awsRegion":
        "us-east-1", "sourceIPAddress": "203.0.113.5", "userAgent":
        "aws-cli", "userIdentity": {
            "type": "AssumedRole", "principalId": "AROAEXAMPLE:session1",
            "arn": "arn:aws:sts::111122223333:assumed-role/DeployRole/"
            "session1", "accountId": "111122223333",
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId":
                                 "AROAEXAMPLE", "arn":
                                 "arn:aws:iam::111122223333:role/"
                                 "DeployRole", "accountId":
                                 "111122223333"},
                "attributes": {"mfaAuthenticated": "false"},
            },
        }, "readOnly": False, "eventID": "evt-assume", "requestID":
        "req-assume", "eventType": "AwsApiCall", "recipientAccountId":
        "111122223333",
    }


def delete_burst_records(n=6, when_start="2026-01-01T01:00:00Z"):
    from datetime import datetime, timedelta
    base = datetime.strptime(when_start, "%Y-%m-%dT%H:%M:%SZ")
    out = []
    for i in range(n):
        t = (base + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out.append({
            "eventVersion": "1.08", "eventTime": t, "eventSource":
            "s3.amazonaws.com", "eventName": "DeleteObject", "awsRegion":
            "us-east-1", "sourceIPAddress": "203.0.113.5", "userAgent":
            "aws-cli", "userIdentity": _iam_user("mallory"),
            "readOnly": False, "eventID": f"evt-del-{i}", "requestID":
            f"req-del-{i}", "eventType": "AwsApiCall",
            "recipientAccountId": "111122223333",
        })
    return out


def write_delivery_file(path: Path, records: list[dict], *,
                        gz: bool = False) -> None:
    payload = json.dumps({"Records": records}).encode("utf-8")
    if gz:
        payload = gzip.compress(payload)
    path.write_bytes(payload)
