from __future__ import annotations

import json

import pytest

from linux_persistence.scan import scan
from linux_persistence.cli import main

import _synth as S


def _scan(tmp_path):
    S.build_tree(tmp_path)
    return scan(str(tmp_path))


def _by_mech(res):
    d = {}
    for f in res.findings:
        d.setdefault(f.mechanism, []).append(f)
    return d


def test_ld_so_preload(tmp_path):
    m = _by_mech(_scan(tmp_path))
    pre = m["ld.so.preload"]
    assert len(pre) == 2
    assert all(f.verdict == "high" for f in pre)
    assert any("/tmp/.x/hook.so" in f.payload for f in pre)


def test_environment_ld_preload(tmp_path):
    m = _by_mech(_scan(tmp_path))
    env = m["environment"]
    assert any("loader variable set" in w for f in env for w in f.why)


def test_shell_rc_cradle(tmp_path):
    m = _by_mech(_scan(tmp_path))
    rc = m["shell-rc"]
    assert any("cradle" in w for f in rc for w in f.why)
    assert any(f.verdict == "high" for f in rc)
    prof = m["profile.d"]
    assert any("user-writable path" in w for f in prof for w in f.why)


def test_rc_local_and_motd(tmp_path):
    m = _by_mech(_scan(tmp_path))
    assert any("user-writable" in w for f in m["rc.local"] for w in f.why)
    motd = m["update-motd.d"]
    assert any("reverse-shell" in w for f in motd for w in f.why)
    assert motd[0].verdict == "high"


def test_pam(tmp_path):
    m = _by_mech(_scan(tmp_path))
    pam = m["pam"]
    assert any("pam_exec.so runs an external program" in w
               for f in pam for w in f.why)
    assert any("absolute / non-standard path" in w for f in pam for w in f.why)
    assert any(f.verdict == "high" for f in pam)
    # benign common-auth produced nothing
    assert all("common-auth" not in f.path for f in pam)


def test_modprobe_and_udev(tmp_path):
    m = _by_mech(_scan(tmp_path))
    km = m["kernel-module"]
    assert any("install= runs a command" in w for f in km for w in f.why)
    ud = m["udev-rule"]
    assert any("RUN{}" in w for f in ud for w in f.why)


def test_sudoers(tmp_path):
    m = _by_mech(_scan(tmp_path))
    su = m["sudoers"]
    assert any("NOPASSWD" in w for f in su for w in f.why)
    assert any("spawn a shell" in w for f in su for w in f.why)
    assert any(f.verdict == "high" for f in su)


def test_systemd_generator(tmp_path):
    m = _by_mech(_scan(tmp_path))
    g = m["systemd-generator"]
    assert g and g[0].verdict == "high"
    assert any("non-standard systemd generator" in w for w in g[0].why)


def test_benign_files_are_quiet(tmp_path):
    res = _scan(tmp_path)
    noisy = [f for f in res.findings if "common-auth" in f.path
             or f.path.endswith("etc/profile")
             or f.path.endswith("lang.sh")
             or f.path.endswith("root/.bashrc")]
    assert noisy == []


def test_cli_csv_json_filters(tmp_path):
    S.build_tree(tmp_path)
    csv_p = tmp_path / "p.csv"
    js_p = tmp_path / "p.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and data

    main([str(tmp_path), "--min-verdict", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["verdict"] == "high" for r in got)

    main([str(tmp_path), "--mechanism", "sudoers,pam", "--json", str(js_p),
          "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["mechanism"] in ("sudoers", "pam") for r in got)


def test_csv_injection_guard():
    from linux_persistence.tracelib import sanitize
    assert sanitize("=RUN()") == "'=RUN()"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
