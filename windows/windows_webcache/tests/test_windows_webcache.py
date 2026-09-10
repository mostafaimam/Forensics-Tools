from __future__ import annotations

import json

import pytest

from windows_webcache.analyze import analyze
from windows_webcache.cli import main

import _synth as S


@pytest.fixture
def wc(tmp_path):
    p = tmp_path / "WebCacheV01.dat"
    p.write_bytes(S.build())
    return p


def _by_url(res):
    return {e.url: e for e in res.entries}


def test_containers_and_classify(wc):
    res = analyze([str(wc)])
    assert res.containers.get("History") == 3
    assert res.containers.get("Cookies") == 1
    hist = [e for e in res.entries if e.entry_type == "history"]
    urls = {e.url for e in hist}
    # the "Visited: user@" prefix is stripped
    assert "http://intranet.corp/wiki" in urls
    assert "https://pastebin.com/raw/AbCdEf12" in urls


def test_timestamps(wc):
    res = analyze([str(wc)])
    e = next(e for e in res.entries if e.url == "http://intranet.corp/wiki")
    assert e.accessed.startswith("2026-03-04T09:05")
    assert e.modified.startswith("2026-03-04T09:00")


def test_cookie_and_download(wc):
    res = analyze([str(wc)])
    ck = next(e for e in res.entries if e.entry_type == "cookie")
    assert ck.url == "ngrok-free.app/"
    dl = next(e for e in res.entries if e.entry_type == "download")
    assert dl.filename == "tool.exe" and dl.size == 2_500_000


def test_flags(wc):
    res = analyze([str(wc)])
    by = _by_url(res)
    assert any("paste / file-sharing / tunnel" in n
               for n in by["https://pastebin.com/raw/AbCdEf12"].notable)
    assert any("IP-literal host" in n
               for n in by["http://185.10.20.30/panel/"].notable)
    dl = next(e for e in res.entries if e.entry_type == "download")
    assert any("executable / script fetched" in n for n in dl.notable)
    ck = next(e for e in res.entries if e.entry_type == "cookie")
    assert any("tunnel site" in n for n in ck.notable)


def test_cli_csv_json_filters(wc, tmp_path):
    csv_p = tmp_path / "w.csv"
    js_p = tmp_path / "w.json"
    rc = main([str(wc), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 6

    main([str(wc), "--type", "download", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["entry_type"] == "download" for r in got)

    main([str(wc), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(wc), "--grep", "pastebin", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("pastebin" in r["url"] for r in got)


def test_csv_injection_guard():
    from windows_webcache.tracelib import sanitize
    assert sanitize("@SUM(1)") == "'@SUM(1)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
