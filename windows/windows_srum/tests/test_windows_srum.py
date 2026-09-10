from __future__ import annotations

import json

import pytest

from windows_srum.analyze import analyze
from windows_srum.cli import main

import _synth as S


@pytest.fixture
def srudb(tmp_path):
    p = tmp_path / "SRUDB.dat"
    p.write_bytes(S.build())
    return p


def test_id_map_and_normalise(srudb):
    res = analyze([str(srudb)])
    assert res.id_map_size == 4
    nd = [r for r in res.rows if r.provider == "network-data"]
    assert len(nd) == 3
    by_app = {r.app.split("\\")[-1]: r for r in nd}
    assert "svchost.exe" in by_app
    assert by_app["svchost.exe"].user == "S-1-5-21-111-222-333-1001"
    assert by_app["svchost.exe"].fields["bytes_recvd"] == 500000
    assert by_app["svchost.exe"].timestamp.startswith("2026-03-01T10:00")


def test_provider_tables(srudb):
    res = analyze([str(srudb)])
    assert set(res.providers_seen) == {"network-data", "application-resource"}
    ar = [r for r in res.rows if r.provider == "application-resource"][0]
    assert ar.fields["fg_cycle_time"] == 5_000_000


def test_flags(srudb):
    res = analyze([str(srudb)])
    by_app = {r.app.split("\\")[-1]: r for r in res.rows
              if r.provider == "network-data"}
    agent = by_app["agent.exe"]
    j = " ".join(agent.notable)
    assert "user-writable path" in j
    assert "large outbound transfer" in j
    assert "upload-only traffic" in j
    assert "writable-path / LOLBin process" in j

    ps = by_app["powershell.exe"]
    assert any("living-off-the-land binary" in n for n in ps.notable)


def test_cli_csv_json(srudb, tmp_path):
    csv_p = tmp_path / "s.csv"
    js_p = tmp_path / "s.json"
    rc = main([str(srudb), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 4
    assert all("provider" in r and "timestamp" in r for r in data)


def test_cli_filters(srudb, tmp_path):
    js_p = tmp_path / "s.json"
    main([str(srudb), "--provider", "network-data", "--min-bytes-sent",
          "10000000", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(int(r["bytes_sent"]) >= 10_000_000 for r in got)

    main([str(srudb), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(srudb), "--app", "powershell", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("powershell" in r["app"].lower() for r in got)


def test_csv_injection_guard():
    from windows_srum.tracelib import sanitize
    assert sanitize("=1+1") == "'=1+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
