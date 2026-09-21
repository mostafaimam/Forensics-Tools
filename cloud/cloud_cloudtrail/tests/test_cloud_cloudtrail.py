from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_cloudtrail.collect import collect
from cloud_cloudtrail.cli import main


def test_console_login_no_mfa_flagged(tmp_path):
    p = tmp_path / "trail1.json"
    S.write_delivery_file(p, [S.console_login_record(mfa=False)])
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["notable"] == "console-login-no-mfa"


def test_console_login_with_mfa_not_flagged(tmp_path):
    p = tmp_path / "trail1.json"
    rec = S.console_login_record(mfa=True)
    rec["userIdentity"]["sessionContext"] = {
        "attributes": {"mfaAuthenticated": "true"}}
    S.write_delivery_file(p, [rec])
    res = collect([str(p)])
    assert "console-login-no-mfa" not in res.rows[0]["notable"]


def test_gzip_delivery_file(tmp_path):
    p = tmp_path / "trail1.json.gz"
    S.write_delivery_file(p, [S.iam_change_record()], gz=True)
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["event_name"] == "CreateUser"


def test_iam_change_flagged(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.iam_change_record("AttachUserPolicy")])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "iam-change"


def test_secret_access_flagged(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.secret_access_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "secret-access"


def test_public_acl_flagged(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.public_acl_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "public-access-change"


def test_root_usage_flagged(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.root_usage_record()])
    res = collect([str(p)])
    assert "root-account-usage" in res.rows[0]["notable"]


def test_assumed_role_arn_captured(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.assumed_role_record()])
    res = collect([str(p)])
    row = res.rows[0]
    assert row["identity_type"] == "AssumedRole"
    assert row["assumed_role_arn"].endswith("role/DeployRole")


def test_delete_burst_flagged(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, S.delete_burst_records(6))
    res = collect([str(p)])
    assert all("delete-burst" in r["notable"] for r in res.rows)


def test_delete_burst_not_flagged_below_threshold(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, S.delete_burst_records(3))
    res = collect([str(p)])
    assert not any("delete-burst" in r["notable"] for r in res.rows)


def test_directory_target_finds_multiple_files(tmp_path):
    (tmp_path / "a.json").write_bytes(
        __import__("json").dumps(
            {"Records": [S.iam_change_record()]}).encode())
    (tmp_path / "b.json.gz").write_bytes(
        __import__("gzip").compress(
            __import__("json").dumps(
                {"Records": [S.secret_access_record()]}).encode()))
    res = collect([str(tmp_path)])
    assert len(res.rows) == 2


def test_no_files_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.console_login_record(mfa=False)])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_notable_only(tmp_path):
    p = tmp_path / "trail.json"
    S.write_delivery_file(p, [S.console_login_record(mfa=True),
                             S.iam_change_record()])
    rec_mfa = S.console_login_record(mfa=True)
    rec_mfa["userIdentity"]["sessionContext"] = {
        "attributes": {"mfaAuthenticated": "true"}}
    S.write_delivery_file(p, [rec_mfa, S.iam_change_record()])
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--notable-only", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["notable"] for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_cloudtrail.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
