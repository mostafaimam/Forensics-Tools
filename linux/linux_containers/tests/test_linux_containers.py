from __future__ import annotations

import json

import pytest

from linux_containers.analyze import analyze
from linux_containers.cli import main

import _synth as S


def _by_name(res):
    return {c.name: c for c in res.containers}


def test_docker_benign(tmp_path):
    S.docker_tree(tmp_path)
    c = _by_name(analyze([str(tmp_path)]))["web"]
    assert c.engine == "docker"
    assert c.image == "nginx:1.25"
    assert c.state == "running"
    assert c.command == "nginx -g daemon off;"
    assert c.entrypoint == "/docker-entrypoint.sh"
    assert c.ports == ["0.0.0.0:8080->80/tcp"]
    assert any(m.dest == "/usr/share/nginx/html" and m.mode == "ro"
               for m in c.mounts)
    assert c.restart_policy == "unless-stopped"
    # user 101, read-only mount, bridge -> only the loose-pin / restart notes
    sev = __import__("linux_containers.flags", fromlist=["severity"]).severity
    assert sev(c.notable) in ("none", "low")


def test_docker_hostile(tmp_path):
    S.docker_tree(tmp_path)
    c = _by_name(analyze([str(tmp_path)]))["ops"]
    assert c.state == "exited" and c.exit_code == "137"
    j = " ".join(c.notable)
    assert "privileged container" in j
    assert "container-runtime socket mounted" in j
    assert "sensitive host path bind-mounted (/ ->" in j
    assert "host network namespace" in j
    assert "host PID namespace" in j
    assert "dangerous capability added (SYS_ADMIN)" in j
    assert "AppArmor disabled" in j and "seccomp disabled" in j
    assert "secret-looking environment variable (DB_PASSWORD)" in j
    assert "cradle / reverse-shell" in j
    assert "host device exposed (/dev/sda)" in j
    assert "image pinned loosely (busybox:latest)" in j
    from linux_containers.flags import severity
    assert severity(c.notable) == "high"


def test_podman(tmp_path):
    S.podman_tree(tmp_path)
    c = _by_name(analyze([str(tmp_path)]))["cache"]
    assert c.engine == "podman"
    assert c.image == "docker.io/library/redis:7"
    assert c.command == "redis-server --appendonly yes"
    assert c.state == "running"
    assert c.user == "999"
    assert any(m.dest == "/data" for m in c.mounts)
    assert not any(m.dest == "/proc" for m in c.mounts)   # implicit mount drop
    j = " ".join(c.notable)
    assert "host PID namespace" in j
    assert "AppArmor disabled" in j
    assert "secret-looking environment variable (REDIS_TOKEN)" in j
    assert "privileged container" in j


def test_containerd(tmp_path):
    S.containerd_tree(tmp_path)
    res = analyze([str(tmp_path)])
    c = res.containers[0]
    assert c.engine == "containerd"
    assert c.image == "pause:3.9"
    assert c.name == "pause"
    assert c.command == "/pause"
    assert "host network namespace" in " ".join(c.notable)


def test_full_tree_engine_tally(tmp_path):
    S.full_tree(tmp_path)
    res = analyze([str(tmp_path)])
    assert res.engines == {"docker": 2, "podman": 1, "containerd": 1}


def test_cli_csv_json_filters(tmp_path):
    S.full_tree(tmp_path)
    csv_p = tmp_path / "c.csv"
    js_p = tmp_path / "c.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and len(data) == 4

    main([str(tmp_path), "--engine", "docker", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["engine"] == "docker" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_grep_and_state(tmp_path):
    S.docker_tree(tmp_path)
    js_p = tmp_path / "c.json"
    main([str(tmp_path), "--state", "exited", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["state"] == "exited" for r in got)


def test_no_runtime_dir(tmp_path):
    (tmp_path / "etc").mkdir()
    res = analyze([str(tmp_path)])
    assert res.containers == []


def test_csv_injection_guard():
    from linux_containers.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
