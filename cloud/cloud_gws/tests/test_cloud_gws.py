from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_gws.collect import collect
from cloud_gws.cli import main


def test_login_failure_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.login_failure()])
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["notable"] == "login-failure"


def test_login_success_not_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.activity()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == ""


def test_suspicious_login_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.suspicious_login()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "suspicious-login"


def test_admin_role_change_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.admin_role_change()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "admin-role-change"
    assert res.rows[0]["target"] == "bob@example.com"


def test_oauth_grant_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.oauth_grant()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "oauth-grant"


def test_external_sharing_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.external_sharing()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == "external-sharing"
    assert res.rows[0]["target"] == "secret-plans.docx"


def test_benign_drive_view_not_flagged(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.benign_drive_view()])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == ""


def test_multiple_events_per_activity(tmp_path):
    act = S.activity()
    act["events"].append({"type": "login", "name": "login_failure",
                          "parameters": []})
    p = tmp_path / "gws.json"
    S.write_export(p, [act])
    res = collect([str(p)])
    assert len(res.rows) == 2
    names = {r["event_name"] for r in res.rows}
    assert names == {"login_success", "login_failure"}


def test_no_files_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.login_failure()])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_application_filter(tmp_path):
    p = tmp_path / "gws.json"
    S.write_export(p, [S.login_failure(), S.oauth_grant()])
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--application", "token", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["application"] == "token" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_gws.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
