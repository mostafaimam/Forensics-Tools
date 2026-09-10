from __future__ import annotations

import json

import pytest

from macos_knowledgec.parse import parse
from macos_knowledgec import flags as _flags
from macos_knowledgec.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "knowledgeC.db"))


def test_parse(db):
    ev = parse(db)
    # default stream filter keeps 7 of 8 (drops /device/isLocked)
    streams = {e.stream_raw for e in ev}
    assert "/app/usage" in streams
    assert "/device/isLocked" not in streams

    pages = next(e for e in ev if e.value == "com.apple.Pages")
    assert pages.stream == "app in focus"
    assert pages.start.startswith("2026-03-12T09:00")
    assert pages.duration_s == 1800
    assert pages.device_id == "MacBookPro18,3"
    assert pages.title == "Q1 report.pages"
    assert pages.gmt_offset == -25200


def test_stream_filter(db):
    ev = parse(db, ["/app/usage"])
    assert ev and all(e.stream_raw == "/app/usage" for e in ev)


def test_flags(db):
    ev = {e.value: e for e in parse(db)}
    term = ev["com.apple.Terminal"]
    assert any("long terminal / script-editor session" in n
               for n in term.notable)

    web = ev["transfer.sh"]
    assert any("paste / file-sharing / tunnel site" in n for n in web.notable)

    intent = ev["Run Shell Script"]
    assert any("Siri / Shortcuts intent that runs a script" in n
               for n in intent.notable)
    assert _flags.severity(intent.notable) == "high"

    spotify = ev["com.spotify.client"]
    assert any("used late at night" in n for n in spotify.notable)

    inst = ev["com.acme.tool"]
    assert any("app install recorded" in n for n in inst.notable)


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "k.csv"
    js_p = tmp_path / "k.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 7

    main([db, "--stream", "/app/usage", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["stream_raw"] == "/app/usage" for r in got)

    main([db, "--app", "Terminal", "--min-duration", "3600",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["duration_s"] >= 3600 for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_mounted_volume(db, tmp_path):
    vol = tmp_path / "mac"
    d = vol / "private/var/db/CoreDuet/Knowledge"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(db, d / "knowledgeC.db")
    js_p = tmp_path / "k.json"
    rc = main([str(vol), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 7


def test_csv_injection_guard():
    from macos_knowledgec.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
