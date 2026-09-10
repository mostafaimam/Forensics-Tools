from __future__ import annotations

import json

import pytest

from linux_packages import parse
from linux_packages.analyze import analyze
from linux_packages.cli import main

import _synth as S


def _events(root):
    return analyze([str(root)]).events


def _by_pkg(events):
    d = {}
    for e in events:
        d.setdefault(e.package, []).append(e)
    return d


def test_parse_dpkg(tmp_path):
    S.dpkg_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert ev["build-essential"][0].action == "install"
    assert ev["build-essential"][0].version == "12.9"
    assert ev["build-essential"][0].ts == "2026-01-04T09:12:34Z"
    up = ev["openssl"][0]
    assert up.action == "upgrade"
    assert up.from_version == "3.0.11-1" and up.version == "3.0.13-1"
    # configure / startup lines are dropped
    assert all(e.action in ("install", "upgrade", "remove", "purge")
               for e in _events(tmp_path))


def test_parse_apt_history(tmp_path):
    S.apt_history(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    be = ev["build-essential"][0]
    assert be.source == "apt"
    assert be.requested_by.startswith("analyst")
    assert "apt-get install" in be.command
    assert ev["openssl"][0].from_version == "3.0.11-1"


def test_parse_yum_text(tmp_path):
    S.yum_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert ev["httpd"][0].action == "install"
    assert ev["openssl"][0].action == "upgrade"
    assert ev["openssl"][0].version == "3.0.7-24.el9"   # epoch stripped
    assert ev["sudo"][0].action == "downgrade"


def test_parse_dnf_text(tmp_path):
    S.dnf_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert ev["git"][0].action == "install"
    assert ev["kernel"][0].action == "upgrade"
    assert ev["socat"][0].ts == "2026-01-06T02:03:17Z"


def test_parse_dnf_history_sqlite(tmp_path):
    S.dnf_history(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert ev["hashcat"][0].action == "install"
    assert ev["hashcat"][0].version == "6.2.6-3.fc39"
    assert ev["hashcat"][0].command == "dnf install hashcat"
    assert ev["openvpn"][0].ts.startswith("2026-01-")


def test_gzip_rotated_log(tmp_path):
    S.dpkg_log_gz(tmp_path, S.DPKG_LOG)
    assert any(e.package == "gcc-12" for e in _events(tmp_path))


def test_flag_toolchain_and_recon(tmp_path):
    S.dpkg_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert any("toolchain" in n for n in ev["build-essential"][0].notable)
    assert any("recon" in n for n in ev["nmap"][0].notable)
    assert any("tunnel" in n for n in ev["tor"][0].notable)


def test_flag_anti_forensic_and_downgrade(tmp_path):
    S.yum_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    assert any("downgraded" in n for n in ev["sudo"][0].notable)


def test_flag_manual_deb_and_shell(tmp_path):
    S.apt_history(tmp_path)
    res = analyze([str(tmp_path)])
    ev = _by_pkg(res.events)
    assert any(".deb" in n for n in ev["sketchy"][0].notable)
    assert any("shell command" in f for f in res.findings)


def test_reinstall_after_removal(tmp_path):
    S.dpkg_log(tmp_path)
    ev = _by_pkg(_events(tmp_path))
    later = [e for e in ev["nmap"] if e.action == "install"]
    assert later and any("after an earlier removal" in n
                         for n in later[-1].notable)


def test_cli_csv_json_filters(tmp_path):
    S.dpkg_log(tmp_path)
    S.apt_history(tmp_path)
    csv_p = tmp_path / "p.csv"
    js_p = tmp_path / "p.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and data

    main([str(tmp_path), "--source", "apt", "--action", "install",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["source"] == "apt" and r["action"] == "install"
                       for r in got)


def test_cli_since_until(tmp_path):
    S.dpkg_log(tmp_path)
    js_p = tmp_path / "p.json"
    main([str(tmp_path), "--since", "2026-02-01", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["ts"][:10] >= "2026-02-01" for r in got)


def test_manifest_sidecar(tmp_path):
    S.dpkg_log(tmp_path)
    csv_p = tmp_path / "p.csv"
    main([str(tmp_path), "--csv", str(csv_p), "-q",
          "--case-id", "C-1", "--examiner", "aa", "--evidence-id", "E-1"])
    m = json.loads((tmp_path / "p.csv.manifest.json").read_text())
    assert m["case_id"] == "C-1"
    assert m["inputs"] and m["inputs"][0]["sha256"]


def test_csv_injection_guard():
    from linux_packages.tracelib import sanitize
    assert sanitize("=cmd|'/bin/sh'") == "'=cmd|'/bin/sh'"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
