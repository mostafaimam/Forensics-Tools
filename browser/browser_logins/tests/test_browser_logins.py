from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from browser_logins import output
from browser_logins.analyze import analyze
from browser_logins.cli import main

import _synth as S

C = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
L = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)


def _by_host(res):
    return {lg.host: lg for lg in res.logins}


def test_chromium_login_data_metadata(tmp_path):
    db = tmp_path / "Login Data"
    S.login_data(db, [
        {"origin": "https://github.com/login", "username": "alice",
         "realm": "https://github.com/", "created": C, "last_used": L,
         "pw_changed": C, "times": 30},
        {"origin": "http://intranet/", "username": "svc_admin",
         "created": C, "last_used": L, "times": 5},
        {"origin": "https://news.example.com/", "blacklisted": True,
         "created": C, "has_pw": False},
    ])
    res = analyze([str(db)])
    by = _by_host(res)
    assert by["github.com"].username == "alice"
    assert by["github.com"].times_used == 30
    assert by["github.com"].has_password_blob is True
    assert by["github.com"].date_last_used == "2026-11-14T09:00:00Z"
    assert any("http://" in x for x in by["intranet"].notable)
    assert any("non-FQDN" in x for x in by["intranet"].notable)
    bl = [lg for lg in res.logins if lg.blacklisted][0]
    assert "never-save" in ";".join(bl.notable)


def test_no_password_in_output(tmp_path):
    db = tmp_path / "Login Data"
    S.login_data(db, [{"origin": "https://x.example/", "username": "bob",
                       "created": C, "times": 1}])
    res = analyze([str(db)])
    blob = json.dumps([output.row(lg) for lg in res.logins])
    assert "password" not in blob.lower() or '"has_password"' in blob
    assert "\\u0001" not in blob                 # no raw blob bytes leaked


def test_firefox_logins_json(tmp_path):
    prof = tmp_path / "abc.default-release"
    prof.mkdir()
    S.firefox_logins(prof / "logins.json", [
        {"hostname": "https://mail.example.com", "realm": None,
         "form_url": "https://mail.example.com/login",
         "created": C, "last_used": L, "times": 12},
    ], disabled=["https://banned.example.com"])
    res = analyze([str(prof / "logins.json")])
    by = _by_host(res)
    assert by["mail.example.com"].browser == "Firefox"
    assert by["mail.example.com"].has_password_blob is True
    assert by["mail.example.com"].username == "(encrypted)"
    assert any(lg.blacklisted and lg.host == "banned.example.com"
               for lg in res.logins)


def test_firefox_primary_password_flag(tmp_path):
    prof = tmp_path / "p.default"
    prof.mkdir()
    S.firefox_logins(prof / "logins.json", [
        {"hostname": "https://x.example", "created": C, "times": 1},
    ], primary_password=True)
    res = analyze([str(prof / "logins.json")])
    assert any("Primary Password" in x for x in res.logins[0].notable)


def test_per_host_finding(tmp_path):
    db = tmp_path / "Login Data"
    rows = [{"origin": f"https://portal.example.com/app{i}",
             "realm": "https://portal.example.com/", "username": f"u{i}",
             "created": C, "last_used": L, "times": 1} for i in range(6)]
    S.login_data(db, rows)
    res = analyze([str(db)])
    assert any("portal.example.com: 6 saved credentials" in f
               for f in res.findings)


def test_folder_walk(tmp_path):
    (tmp_path / "Chrome").mkdir()
    (tmp_path / "ff.default").mkdir()
    S.login_data(tmp_path / "Chrome" / "Login Data",
                 [{"origin": "https://a.example/", "username": "x",
                   "created": C, "times": 1}])
    S.firefox_logins(tmp_path / "ff.default" / "logins.json",
                     [{"hostname": "https://b.example", "created": C}])
    res = analyze([str(tmp_path)])
    assert res.stores == 2
    assert {lg.browser for lg in res.logins} == {"Chrome", "Firefox"}


def test_cli_csv_json_filters(tmp_path):
    db = tmp_path / "Login Data"
    S.login_data(db, [
        {"origin": "https://github.com/", "username": "alice", "created": C,
         "last_used": L, "times": 3},
        {"origin": "https://gitlab.com/", "username": "bob", "created": C,
         "last_used": L, "times": 1},
        {"origin": "https://x.example/", "blacklisted": True, "created": C},
    ])
    csv_p = tmp_path / "l.csv"
    js_p = tmp_path / "l.json"
    rc = main([str(db), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    # blacklist excluded by default
    assert len(json.loads(js_p.read_text())) == 2

    main([str(db), "--include-blacklist", "--json", str(js_p), "-q"])
    assert len(json.loads(js_p.read_text())) == 3

    main([str(db), "--host", "github", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["username"] == "alice"


def test_csv_injection_guard():
    assert output._san("=1+1") == "'=1+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
