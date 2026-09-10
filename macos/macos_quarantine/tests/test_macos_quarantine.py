from __future__ import annotations

import json

import pytest

from macos_quarantine.parse import parse
from macos_quarantine import flags as _flags
from macos_quarantine.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "QuarantineEventsV2"))


def test_parse(db):
    ev = parse(db)
    assert len(ev) == 5
    a1 = ev[0]
    assert a1.agent_name == "Safari"
    assert a1.data_url.endswith("report.pdf")
    assert a1.origin_url == "https://example.com/reports"
    assert a1.timestamp == "2026-03-10T09:00:00Z"
    assert a1.event_type == "web download"


def test_flags(db):
    ev = {e.identifier: e for e in parse(db)}
    assert any("Installer.dmg" not in n and "installer / script" in n
               for n in ev["A2"].notable) or \
        any("installer" in n for n in ev["A2"].notable)
    term = ev["A3"]
    j = " ".join(term.notable)
    assert "command-line / scripting agent (Terminal)" in j
    assert "IP-literal host" in j
    assert _flags.severity(term.notable) == "high"

    mail = ev["A4"]
    assert any("email attachment" in n for n in mail.notable)

    ff = ev["A5"]
    assert any("file-sharing / tunnel site" in n for n in ff.notable)


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "q.csv"
    js_p = tmp_path / "q.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 5

    main([db, "--agent", "Terminal", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["agent_name"] == "Terminal" for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([db, "--grep", "transfer.sh", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got


def test_cli_mounted_volume(db, tmp_path):
    vol = tmp_path / "mac"
    d = vol / "Users/victim/Library/Preferences"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(db, d / "com.apple.LaunchServices.QuarantineEventsV2")
    js_p = tmp_path / "q.json"
    rc = main([str(vol), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 5


def test_csv_injection_guard():
    from macos_quarantine.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
