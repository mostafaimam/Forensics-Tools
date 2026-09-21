from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_m365ual.collect import collect
from cloud_m365ual.cli import main


def test_mail_forwarding_rule_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.mail_forwarding_rule_record()])
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["notable"] == "mail-forwarding-rule"
    assert "ForwardTo=attacker@evil.example" in res.rows[0]["details"]


def test_benign_inbox_rule_not_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.benign_inbox_rule_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == ""


def test_consent_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.consent_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "app-consent"


def test_role_grant_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.role_grant_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "role-grant"


def test_mailbox_permission_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.mailbox_permission_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "mailbox-permission-change"


def test_failed_operation_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.failed_record()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "operation-failed"


def test_mass_download_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, S.download_burst_records(12))
    res = collect([str(p)])
    assert all("mass-download" in r["notable"] for r in res.rows)


def test_download_below_threshold_not_flagged(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, S.download_burst_records(3))
    res = collect([str(p)])
    assert not any("mass-download" in r["notable"] for r in res.rows)


def test_csv_export_parsed(tmp_path):
    p = tmp_path / "ual.csv"
    S.write_csv_export(p, [S.consent_record()])
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["operation"] == "Consent to application"
    assert res.rows[0]["notable"] == "app-consent"


def test_workload_and_user_present(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.mail_forwarding_rule_record()])
    res = collect([str(p)])
    row = res.rows[0]
    assert row["workload"] == "Exchange"
    assert row["user"] == "alice@contoso.com"
    assert row["client_ip"] == "203.0.113.5"


def test_no_files_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.mail_forwarding_rule_record()])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_workload_filter(tmp_path):
    p = tmp_path / "ual.json"
    S.write_json_export(p, [S.mail_forwarding_rule_record(),
                            S.consent_record()])
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--workload", "Exchange", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["workload"] == "Exchange" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_m365ual.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
