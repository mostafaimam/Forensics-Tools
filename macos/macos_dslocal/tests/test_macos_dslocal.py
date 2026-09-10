from __future__ import annotations

import json

import pytest

from macos_dslocal.parse import collect
from macos_dslocal import flags as _flags
from macos_dslocal.cli import main

import _synth as S


@pytest.fixture
def vol(tmp_path):
    return S.build_node(tmp_path / "mac")


def _by_name(res):
    return {u.name: u for u in res.users}


def test_parse_users(vol):
    res = collect(str(vol))
    assert len(res.users) == 7
    v = _by_name(res)["victim"]
    assert v.uid == 501 and v.gid == 20
    assert v.realname == "Victim User"
    assert v.shell == "/bin/zsh"
    assert "ShadowHash" in v.auth_mechanisms
    assert v.pbkdf2_iterations == 200000
    assert v.hint == "Fluffy2019!"
    assert v.created == "2023-11-14T22:13:20Z"
    assert v.failed_count == 2


def test_group_membership(vol):
    res = collect(str(vol))
    by = _by_name(res)
    assert by["admin"].is_admin is True
    assert by["victim"].is_admin is False
    assert "staff" in by["victim"].groups


def test_flags(vol):
    res = collect(str(vol))
    by = _by_name(res)

    assert any("password hint may contain the password" in n
               for n in by["victim"].notable)
    assert any("member of the 'admin' group" in n for n in by["admin"].notable)

    svc = by["svc-helper"]
    assert any("hidden account (uid 401) with an interactive shell" in n
               for n in svc.notable)
    assert _flags.severity(svc.notable) == "high"

    guest = by["guestx"]
    assert any("no configured password and an interactive shell" in n
               for n in guest.notable)

    backup = by["backup"]
    assert any("home directory outside /Users (/opt/backup-home/backup)" in n
               for n in backup.notable)

    # root / _spotlight are quiet
    assert not by["root"].notable
    assert not by["_spotlight"].notable


def test_cli_csv_json(vol, tmp_path):
    csv_p = tmp_path / "d.csv"
    js_p = tmp_path / "d.json"
    rc = main([str(vol), "--include-service", "--csv", str(csv_p),
               "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 7

    # default hides quiet _service accounts
    main([str(vol), "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert "_spotlight" not in {r["name"] for r in got}

    main([str(vol), "--admins-only", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["is_admin"] == "yes" for r in got)

    main([str(vol), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_single_user_plist(vol, tmp_path):
    p = (vol / "private/var/db/dslocal/nodes/Default/users/victim.plist")
    js_p = tmp_path / "d.json"
    rc = main([str(p), "--json", str(js_p), "-q"])
    assert rc == 0
    got = json.loads(js_p.read_text())
    assert len(got) == 1 and got[0]["name"] == "victim"


def test_csv_injection_guard():
    from macos_dslocal.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
