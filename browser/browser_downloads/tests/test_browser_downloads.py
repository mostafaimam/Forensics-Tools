from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from browser_downloads import flags, output
from browser_downloads.analyze import analyze
from browser_downloads.cli import main

import _synth as S

T0 = datetime(2026, 11, 14, 9, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 11, 14, 9, 5, 0, tzinfo=timezone.utc)


def _by_name(res):
    return {d.filename: d for d in res.downloads}


def test_chromium_downloads(tmp_path):
    hist = tmp_path / "History"
    S.chromium_history(hist, [
        {"url": "https://example.com/report.pdf",
         "target": str(tmp_path / "dl" / "report.pdf"),
         "start": T0, "end": T1, "received": 12000, "total": 12000,
         "state": 1, "mime": "application/pdf",
         "referrer": "https://example.com/"},
        {"url": "http://192.168.1.9/tool.exe",
         "chain": ["http://redir.example.net/go", "http://192.168.1.9/tool.exe"],
         "target": str(tmp_path / "dl" / "tool.exe"),
         "start": T0, "end": T1, "received": 900000, "total": 900000,
         "state": 1, "danger": 1, "mime": "application/x-msdownload"},
    ])
    res = analyze([str(hist)], scan_fs=False)
    d = _by_name(res)
    assert set(d) == {"report.pdf", "tool.exe"}
    assert d["report.pdf"].url == "https://example.com/report.pdf"
    assert d["report.pdf"].start_time == "2026-11-14T09:00:00Z"
    # url chain: first link is the original request URL
    assert d["tool.exe"].url == "http://redir.example.net/go"
    n = d["tool.exe"].notable
    assert any("executable / script download" in x for x in n)
    assert any("browser danger flag" in x for x in n)
    assert output.row(d["tool.exe"])["severity"] == "high"


def test_firefox_places_downloads(tmp_path):
    places = tmp_path / "places.sqlite"
    S.firefox_places(places, [
        {"url": "https://mozilla.org/firefox.dmg",
         "dest": "file:///Users/x/Downloads/firefox.dmg",
         "added": T0, "modified": T1, "size": 55000, "state": 1},
    ])
    res = analyze([str(places)], scan_fs=False)
    d = _by_name(res)
    assert "firefox.dmg" in d
    assert d["firefox.dmg"].browser == "Firefox"
    assert d["firefox.dmg"].received_bytes == 55000


def test_partial_file_on_disk(tmp_path):
    dl = tmp_path / "Downloads"
    dl.mkdir()
    (dl / "bigfile.iso.crdownload").write_bytes(b"\x00" * 4096)
    res = analyze([str(dl)])
    d = _by_name(res)
    assert "bigfile.iso" in d                      # partial ext stripped
    part = d["bigfile.iso"]
    assert part.on_disk == "partial" and part.disk_size == 4096
    assert any("partial-download file left on disk (bigfile.iso.crdownload)"
               in x for x in part.notable)


def test_zone_identifier_standalone(tmp_path):
    dl = tmp_path / "Downloads"
    dl.mkdir()
    target = dl / "invoice.exe"
    target.write_bytes(b"MZ" + b"\x00" * 1000)
    S.zone_identifier(target, zone_id="3",
                      host="http://45.9.148.200/invoice.exe",
                      referrer="https://mail.example.com/")
    res = analyze([str(dl)])
    d = _by_name(res)
    assert "invoice.exe" in d
    z = d["invoice.exe"]
    assert z.zone_id == "3"
    assert z.zone_host == "http://45.9.148.200/invoice.exe"
    joined = " ".join(z.notable)
    assert "internet-zone (MOTW) executable" in joined
    assert "downloaded from a raw IP" in joined


def test_history_correlated_with_disk_and_zone(tmp_path):
    dl = tmp_path / "Downloads"
    dl.mkdir()
    target = dl / "setup.msi"
    target.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 2048)
    S.zone_identifier(target, zone_id="3", host="https://cdn.example.com/setup.msi",
                      referrer="https://download.example.com/")
    hist = tmp_path / "History"
    S.chromium_history(hist, [
        {"url": "https://cdn.example.com/setup.msi", "target": str(target),
         "start": T0, "end": T1, "received": 2052, "total": 2052, "state": 1,
         "mime": "application/x-msi"},
    ])
    res = analyze([str(hist), str(dl)])
    d = _by_name(res)
    assert "setup.msi" in d
    row = d["setup.msi"]
    assert row.source == "history-db"
    assert row.on_disk == "present" and row.disk_size == 2052
    assert row.zone_id == "3"
    assert any("executable / script download" in x for x in row.notable)


def test_double_extension_and_mime_mismatch(tmp_path):
    hist = tmp_path / "History"
    S.chromium_history(hist, [
        {"url": "https://x.example/photo.jpg.exe",
         "target": str(tmp_path / "photo.jpg.exe"), "start": T0, "end": T1,
         "received": 10, "state": 1, "mime": "image/jpeg"},
    ])
    res = analyze([str(hist)], scan_fs=False)
    n = list(res.downloads)[0].notable
    assert any("double extension" in x for x in n)
    assert any("MIME / extension mismatch" in x for x in n)


def test_missing_file_flagged(tmp_path):
    hist = tmp_path / "History"
    S.chromium_history(hist, [
        {"url": "https://x/gone.zip", "target": str(tmp_path / "gone.zip"),
         "start": T0, "end": T1, "received": 5, "state": 1},
    ])
    res = analyze([str(hist), str(tmp_path)])
    assert list(res.downloads)[0].on_disk == "missing"


def test_cli_csv_json_filters(tmp_path):
    hist = tmp_path / "History"
    S.chromium_history(hist, [
        {"url": "https://x/a.pdf", "target": str(tmp_path / "a.pdf"),
         "start": T0, "end": T1, "received": 10, "state": 1,
         "mime": "application/pdf"},
        {"url": "https://x/b.exe", "target": str(tmp_path / "b.exe"),
         "start": T0, "end": T1, "received": 10, "state": 1},
    ])
    csv_p = tmp_path / "d.csv"
    js_p = tmp_path / "d.json"
    rc = main([str(hist), "--no-fs", "--csv", str(csv_p), "--json",
               str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 2

    main([str(hist), "--no-fs", "--notable-only", "--json", str(js_p), "-q"])
    only = json.loads(js_p.read_text())
    assert len(only) == 1 and only[0]["filename"] == "b.exe"

    main([str(hist), "--no-fs", "--grep", r"\.pdf$", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["filename"] == "a.pdf"


def test_csv_injection_guard():
    assert output._san("=HYPERLINK()") == "'=HYPERLINK()"
    assert output._san("normal.exe") == "normal.exe"


def test_flag_helpers():
    from browser_downloads.model import Download
    d = Download(url="http://8.8.8.8/x.scr", target_path="/tmp/x.scr")
    n = flags.flag(d)
    assert any("executable" in x for x in n)
    assert any("raw IP" in x for x in n)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
