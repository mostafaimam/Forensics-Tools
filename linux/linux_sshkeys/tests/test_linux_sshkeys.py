from __future__ import annotations

import json

import pytest

from linux_sshkeys import keys as K
from linux_sshkeys.collect import collect
from linux_sshkeys.cli import main

import _synth as S


def _collect(tmp_path):
    S.build_tree(tmp_path)
    return collect(str(tmp_path))


def test_authorized_keys_parse(tmp_path):
    res = _collect(tmp_path)
    ak = [k for k in res.keys if k.kind == "authorized_key"]
    assert {k.user for k in ak} == {"root", "deploy"}
    admin = next(k for k in ak if k.comment == "admin@corp")
    assert admin.key_type == "ssh-ed25519"
    assert admin.sha256.startswith("SHA256:")
    assert admin.md5.startswith("MD5:")


def test_rsa_bits_and_weak_flags(tmp_path):
    res = _collect(tmp_path)
    legacy = next(k for k in res.keys
                  if k.kind == "authorized_key" and k.comment == "legacy")
    assert 1000 <= legacy.bits <= 1030
    assert any("short RSA key" in n for n in legacy.notable)


def test_option_flags(tmp_path):
    res = _collect(tmp_path)
    ak = {k.comment: k for k in res.keys if k.kind == "authorized_key"}
    assert any("no from= restriction" in n for n in ak["admin@corp"].notable)
    assert any("shell / tool" in n for n in ak["pwn@kali"].notable)
    assert any("environment=" in n for n in ak["env-key"].notable)
    assert any("notable key comment" in n for n in ak["pwn@kali"].notable)
    # the from=10/8 key is restricted -> no "no from=" flag
    assert not any("no from=" in n for n in ak["restricted@corp"].notable)


def test_known_hosts(tmp_path):
    res = _collect(tmp_path)
    kh = [k for k in res.keys if k.kind == "known_host"]
    ca = next(k for k in kh if k.marker == "@cert-authority")
    assert any("@cert-authority" in n for n in ca.notable)
    assert any(k.hashed_host and k.hosts == "<hashed>" for k in kh)


def test_host_keys_and_private(tmp_path):
    res = _collect(tmp_path)
    hk = [k for k in res.keys if k.kind == "host_key"]
    assert any(k.key_type == "ssh-dss" for k in hk)
    assert any("DSA host key" in n for k in hk for n in k.notable)

    priv = {__import__("pathlib").Path(p.source).name: p for p in res.private}
    assert priv["id_ed25519"].fmt == "openssh"
    assert priv["id_ed25519"].encrypted is False
    assert priv["id_rsa"].fmt == "pem-rsa"
    assert priv["id_rsa"].encrypted is True
    assert priv["ssh_host_ed25519_key"].encrypted is True
    assert priv["ssh_host_ed25519_key"].cipher == "aes256-ctr"


def test_private_key_format_detection():
    assert K.parse_private_key(S.OPENSSH_PRIV_ENC, "x").cipher == "aes256-ctr"
    assert K.parse_private_key(S.PEM_RSA_UNENC, "x").encrypted is False
    assert K.parse_private_key("not a key", "x") is None


def test_sshd_config_review(tmp_path):
    res = _collect(tmp_path)
    msgs = {f["message"] for f in res.config_findings}
    assert any("root login permitted (yes)" in m for m in msgs)
    assert any("password authentication enabled" in m for m in msgs)
    assert any("PermitUserEnvironment yes" in m for m in msgs)
    assert any("AuthorizedKeysCommand" in m for m in msgs)
    assert any("PermitTunnel" in m for m in msgs)
    assert any("LogLevel QUIET" in m for m in msgs)
    assert any("weak cipher" in m for m in msgs)
    # Match block directive carries its condition
    fc = next(f for f in res.config_findings if f["keyword"] == "ForceCommand")
    assert fc["match"] == "User deploy"


def test_cli_csv_json_filters(tmp_path):
    S.build_tree(tmp_path)
    csv_p = tmp_path / "s.csv"
    js_p = tmp_path / "s.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and data
    kinds = {r["kind"] for r in data}
    assert {"authorized_key", "known_host", "host_key", "private_key",
            "config-finding"} <= kinds

    main([str(tmp_path), "--kind", "authorized_key", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["kind"] == "authorized_key" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_all_directives_flag(tmp_path):
    S.build_tree(tmp_path)
    js_p = tmp_path / "s.json"
    main([str(tmp_path), "--all-directives", "--kind", "config",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert any(r["keyword"] == "Port" and r["value"] == "22" for r in got)


def test_csv_injection_guard():
    from linux_sshkeys.tracelib import sanitize
    assert sanitize('=cmd|"x"') == "'=cmd|\"x\""


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
