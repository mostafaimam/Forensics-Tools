from __future__ import annotations

import json

import pytest

from windows_notifications.parse import parse, _payload_text
from windows_notifications import flags as _flags
from windows_notifications.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "wpndatabase.db"))


def test_payload_text():
    xml = S.TOAST.format(title="Hi", body="there friend")
    assert _payload_text(xml) == "Hi | there friend"


def test_parse_and_join(db):
    notes = parse(db)
    assert len(notes) == 4
    by_app = {n.app.split("\\")[-1]: n for n in notes}
    assert "Microsoft.Windows.Explorer" in [n.app for n in notes]
    dl = next(n for n in notes if "Download complete" in n.text)
    assert dl.ntype == "toast"
    assert dl.arrival.startswith("2026-03-09T09:00")
    assert dl.expiry.startswith("2026-03-09T20:00")
    ps = by_app["powershell.exe"]
    assert ps.app.endswith("powershell.exe")


def test_raw_and_types(db):
    notes = parse(db)
    raw = next(n for n in notes if n.ntype == "raw")
    assert raw.tag == "beacon"


def test_flags(db):
    notes = parse(db)
    ps = next(n for n in notes if n.app.endswith("powershell.exe"))
    j = " ".join(ps.notable)
    assert "script / LOLBin app" in j
    assert "contains a URL" in j
    assert _flags.severity(ps.notable) == "high"

    agent = next(n for n in notes if "agent.exe" in n.app)
    assert any("user-writable path" in n for n in agent.notable)
    assert any("raw notification" in n for n in agent.notable)

    code = next(n for n in notes if "login code" in n.text)
    assert any("authentication code" in n for n in code.notable)


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "n.csv"
    js_p = tmp_path / "n.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 4

    main([db, "--type", "raw", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["type"] == "raw" for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([db, "--grep", "185.10", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got


def test_cli_mounted_root(db, tmp_path):
    root = tmp_path / "img"
    d = root / "Users/victim/AppData/Local/Microsoft/Windows/Notifications"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(db, d / "wpndatabase.db")
    js_p = tmp_path / "n.json"
    rc = main([str(root), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 4


def test_csv_injection_guard():
    from windows_notifications.tracelib import sanitize
    assert sanitize("+1") == "'+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
