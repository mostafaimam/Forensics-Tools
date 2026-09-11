from __future__ import annotations

import json

import pytest

import _synth as S

from macos_coreanalytics.parse import load_bytes
from macos_coreanalytics.records import extract
from macos_coreanalytics.collect import collect
from macos_coreanalytics.cli import main


def test_plist_form():
    kind, doc = load_bytes(S.build_plist())
    assert kind == "plist"
    recs = extract(doc, "x")
    assert len(recs) == 2
    r = recs[0]
    assert r.app == "com.apple.Safari"
    assert r.timestamp == "2026-03-16T09:00:00Z"
    assert r.launches == "5"
    assert r.foreground_seconds == "3600"


def test_ndjson_form():
    kind, doc = load_bytes(S.build_ndjson())
    assert kind == "ndjson"
    recs = extract(doc, "y")
    assert len(recs) == 2
    assert recs[0].app == "com.apple.Mail"
    assert recs[0].active_seconds == "900"
    assert recs[1].event_name == "com.apple.something.unstructured"


def test_collect(tmp_path):
    (tmp_path / "Analytics-2026-03-16-090000.core_analytics").write_bytes(
        S.build_plist())
    (tmp_path / "Analytics-2026-03-15-080000.core_analytics").write_bytes(
        S.build_ndjson())
    res = collect([str(tmp_path)])
    assert res.files == 2
    assert len(res.rows) == 4
    apps = {r["app"] for r in res.rows}
    assert "com.apple.Safari" in apps
    assert "com.apple.Mail" in apps


def test_cli(tmp_path):
    (tmp_path / "a.core_analytics").write_bytes(S.build_plist())
    js = tmp_path / "o.json"
    csv = tmp_path / "o.csv"
    rc = main([str(tmp_path), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert len(rows) == 2

    main([str(tmp_path), "--app", "suspicious", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and got[0]["app"] == "com.suspicious.tool"


def test_csv_injection_guard():
    from macos_coreanalytics.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
