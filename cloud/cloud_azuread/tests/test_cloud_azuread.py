from __future__ import annotations

import json

import pytest

import _synth as S

from cloud_azuread.collect import collect
from cloud_azuread.cli import main


def test_signin_success_not_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record()])
    res = collect([str(p)])
    assert not res.warnings
    assert res.rows[0]["kind"] == "signin"
    assert res.rows[0]["notable"] == ""


def test_signin_failure_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record(error_code=50126)])
    res = collect([str(p)])
    assert "signin-failure" in res.rows[0]["notable"]


def test_legacy_auth_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record(client_app="IMAP")])
    res = collect([str(p)])
    assert "legacy-auth" in res.rows[0]["notable"]


def test_risky_signin_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record(risk_state="atRisk")])
    res = collect([str(p)])
    assert "risky-signin" in res.rows[0]["notable"]


def test_ca_failure_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record(ca_status="failure")])
    res = collect([str(p)])
    assert "ca-failure" in res.rows[0]["notable"]


def test_new_country_flagged(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [
        S.signin_record(country="US", when="2026-01-01T00:00:00Z"),
        S.signin_record(country="US", when="2026-01-01T01:00:00Z"),
        S.signin_record(country="RU", when="2026-01-01T02:00:00Z"),
    ])
    res = collect([str(p)])
    by_time = sorted(res.rows, key=lambda r: r["time"])
    assert by_time[0]["notable"] == ""
    assert by_time[1]["notable"] == ""
    assert "new-country" in by_time[2]["notable"]


def test_audit_sensitive_activity_flagged(tmp_path):
    p = tmp_path / "audit.json"
    S.write_export(p, [S.audit_record()])
    res = collect([str(p)])
    assert res.rows[0]["kind"] == "audit"
    assert res.rows[0]["notable"] == "sensitive-activity"
    assert res.rows[0]["targets"] == "Global Administrator"


def test_audit_benign_activity_not_flagged(tmp_path):
    p = tmp_path / "audit.json"
    S.write_export(p, [S.audit_record(activity="Update user")])
    res = collect([str(p)])
    assert res.rows[0]["notable"] == ""


def test_bare_array_export(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record()], wrapped=False)
    res = collect([str(p)])
    assert not res.warnings
    assert len(res.rows) == 1


def test_mixed_signin_and_audit(tmp_path):
    p = tmp_path / "mixed.json"
    S.write_export(p, [S.signin_record(), S.audit_record()])
    res = collect([str(p)])
    kinds = {r["kind"] for r in res.rows}
    assert kinds == {"signin", "audit"}


def test_no_files_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_cli_csv_json(tmp_path):
    p = tmp_path / "signins.json"
    S.write_export(p, [S.signin_record(client_app="IMAP")])
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows


def test_cli_kind_filter(tmp_path):
    p = tmp_path / "mixed.json"
    S.write_export(p, [S.signin_record(), S.audit_record()])
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--kind", "audit", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["kind"] == "audit" for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from cloud_azuread.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
