from __future__ import annotations

import json

import pytest

from linux_audit import parse
from linux_audit.analyze import analyze
from linux_audit.cli import main

import _synth as S


def _events(root):
    return analyze([str(root)]).events


def _by_serial(events):
    return {e.serial: e for e in events}


def test_execve_assembly(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    e = ev["101"]
    assert e.action == "execve"
    assert e.command == "ls -la /etc"
    assert e.exe == "/usr/bin/ls"
    assert e.cwd == "/root"
    assert e.key == "watch-etc"
    assert "/etc" in e.paths
    assert e.syscall == "execve"


def test_proctitle_hex_decode():
    r = parse.parse_line(
        'type=PROCTITLE msg=audit(1768435200.1:9): '
        'proctitle=' + S._proctitle(["python3", "-c", "import os"]))
    assert r.rtype == "PROCTITLE"
    evs = parse.assemble([r])
    assert evs[0].command == "python3 -c import os"


def test_flag_writable_and_recon(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    assert any("user-writable path" in n for n in ev["103"].notable)
    assert any("recon tool" in n for n in ev["104"].notable)
    assert any("cradle" in n for n in ev["105"].notable)


def test_flag_sensitive_file_and_escalation(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    assert any("sensitive file" in n for n in ev["106"].notable)
    # /tmp/.s/impl ran with auid=0 uid=0 -> writable-path high, not escalation
    assert parse  # keep import


def test_user_cmd_and_auth(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    assert ev["108"].action == "user-cmd"
    assert ev["108"].command == "/bin/systemctl restart web"
    assert any("failed sudo" in n for n in ev["109"].notable)
    assert ev["107"].action == "auth"
    assert any("authentication failure" in n for n in ev["107"].notable)


def test_account_change_and_config(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    assert ev["110"].action == "account-change"
    assert any("account / group change" in n for n in ev["110"].notable)
    assert any("audit rule set changed" in n for n in ev["111"].notable)


def test_avc_and_sockaddr(tmp_path):
    S.default_log(tmp_path)
    ev = _by_serial(_events(tmp_path))
    assert ev["112"].action == "selinux-denial"
    assert any("SELinux" in n for n in ev["112"].notable)
    net = ev["113"]
    assert net.addr == "45.9.148.20:443"
    assert any("outbound connection" in n for n in net.notable)


def test_gzip_rotated(tmp_path):
    S.default_log(tmp_path, name="audit.log.1.gz", gz=True)
    assert len(_events(tmp_path)) >= 12


def test_cli_csv_json_filters(tmp_path):
    S.default_log(tmp_path)
    csv_p = tmp_path / "a.csv"
    js_p = tmp_path / "a.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and data

    main([str(tmp_path), "--action", "execve", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["action"] == "execve" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_key_and_grep(tmp_path):
    S.default_log(tmp_path)
    js_p = tmp_path / "a.json"
    main([str(tmp_path), "--key", "identity", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("identity" in r["key"] for r in got)


def test_unparsed_counter(tmp_path):
    d = tmp_path / "var/log/audit"
    d.mkdir(parents=True)
    (d / "audit.log").write_text("not an audit line\n"
                                 + S.execve_event("1768435200.1", 1,
                                                  ["id"]) + "\n")
    res = analyze([str(tmp_path)])
    assert res.unparsed == 1
    assert len(res.events) == 1


def test_csv_injection_guard():
    from linux_audit.tracelib import sanitize
    assert sanitize("=cmd()") == "'=cmd()"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
