from __future__ import annotations

import json

import pytest

from macos_netusage.parse import parse
from macos_netusage import flags as _flags
from macos_netusage.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "netusage.sqlite"))


def _by_proc(res):
    return {p.process: p for p in res.processes}


def test_parse_and_aggregate(db):
    res = parse(db)
    assert len(res.processes) == 5
    by = _by_proc(res)
    safari = by["com.apple.Safari"]
    assert safari.wifi_in == 70_000_000        # two rows summed
    assert safari.wifi_out == 3_500_000
    assert safari.rows == 2
    assert safari.first_seen.startswith("2026-03-15T09:00")
    assert safari.last_seen.startswith("2026-03-15T12:00")

    agent = by["/Users/victim/.cache/agent"]
    assert agent.total_out == 255_000_000
    assert agent.wwan_out == 2_000_000


def test_attachments(db):
    res = parse(db)
    assert len(res.attachments) == 2
    ids = {a.identifier for a in res.attachments}
    assert "CorpWiFi" in ids and "iPhone Hotspot" in ids


def test_flags(db):
    res = parse(db)
    by = _by_proc(res)

    agent = by["/Users/victim/.cache/agent"]
    j = " ".join(agent.notable)
    assert "large outbound transfer" in j
    assert "process in a user-writable path" in j
    assert "cellular (WWAN) usage" in j
    assert _flags.severity(agent.notable) == "high"

    curl = by["curl"]
    j = " ".join(curl.notable)
    assert "shell / scripting / transfer tool (curl)" in j
    assert "upload-heavy traffic" in j

    assert not by["com.apple.Safari"].notable
    assert not by["Spotify"].notable       # download-heavy, not upload


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "n.csv"
    js_p = tmp_path / "n.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 5
    # sorted by total_out desc
    assert data[0]["process"] == "/Users/victim/.cache/agent"

    main([db, "--min-out", "1000000", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["total_out"] >= 1_000_000 for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([db, "--attachments", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert len(got) == 2 and "identifier" in got[0]


def test_cli_mounted_volume(db, tmp_path):
    vol = tmp_path / "mac"
    d = vol / "private/var/networkd"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(db, d / "netusage.sqlite")
    js_p = tmp_path / "n.json"
    rc = main([str(vol), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 5


def test_csv_injection_guard():
    from macos_netusage.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
