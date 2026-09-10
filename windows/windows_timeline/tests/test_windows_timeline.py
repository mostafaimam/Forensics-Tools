from __future__ import annotations

import json

import pytest

from windows_timeline.parse import parse
from windows_timeline import flags as _flags
from windows_timeline.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "ActivitiesCache.db"))


def test_parse_activities(db):
    acts = parse(db)
    assert len(acts) == 5           # 4 Activity + 1 ActivityOperation
    by_disp = {a.display_text: a for a in acts}
    word = by_disp["Q1 report.docx"]
    assert word.activity_type == "open-app-or-file"
    assert word.app.endswith("WINWORD.EXE")
    assert "Q1%20report.docx" in word.content_uri
    assert word.start.startswith("2026-03-07T09:00")
    assert word.duration_s == 1500
    assert word.is_local_only is True


def test_app_resolution_and_operation(db):
    acts = parse(db)
    op = next(a for a in acts if a.from_operation)
    assert op.app.endswith("cmd.exe")
    packaged = next(a for a in acts if "Notepad" in a.app)
    assert packaged.app.startswith("Microsoft.WindowsNotepad")


def test_clipboard_decode(db):
    acts = parse(db)
    clip = next(a for a in acts if a.activity_type == "clipboard")
    assert "aws_secret_access_key" in clip.clipboard_text


def test_flags(db):
    acts = parse(db)
    by = {a.display_text: a for a in acts}
    agent = by["agent.exe"]
    j = " ".join(agent.notable)
    assert "user-writable path" in j
    assert _flags.severity(agent.notable) == "high"

    ps = by["Windows PowerShell"]
    assert any("living-off-the-land" in n for n in ps.notable)

    clip = next(a for a in acts if a.activity_type == "clipboard")
    assert any("secret-looking string" in n for n in clip.notable)

    op = next(a for a in acts if a.from_operation)
    assert any("ActivityOperation" in n for n in op.notable)


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "t.csv"
    js_p = tmp_path / "t.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 5

    main([db, "--type", "clipboard", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["activity_type"] == "clipboard" for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([db, "--grep", "powershell", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got


def test_cli_mounted_root(db, tmp_path):
    root = tmp_path / "img"
    d = root / "Users/victim/AppData/Local/ConnectedDevicesPlatform/L.abc"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(db, d / "ActivitiesCache.db")
    js_p = tmp_path / "t.json"
    rc = main([str(root), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 5


def test_csv_injection_guard():
    from windows_timeline.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
