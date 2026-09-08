from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone

import pytest

from browser_cache import output, simplecache
from browser_cache.analyze import analyze
from browser_cache.cli import main

import _synth as S

R = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)
Q = datetime(2026, 11, 14, 8, 59, tzinfo=timezone.utc)

HTML = b"<!doctype html><title>hi</title>" + b"x" * 400
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 500
MZ = b"MZ\x90\x00" + b"\x00" * 4000


def _by_url(res):
    return {e.url: e for e in res.entries}


def test_simple_cache_basic(tmp_path):
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://example.com/index.html", "body": HTML,
         "status": 200, "ctype": "text/html", "req_time": Q, "resp_time": R,
         "extra_headers": ["Server: nginx", "ETag: \"abc123\""]},
        {"url": "https://example.com/logo.png", "body": PNG,
         "ctype": "image/png", "resp_time": R},
    ])
    res = analyze([str(cd)])
    by = _by_url(res)
    e = by["https://example.com/index.html"]
    assert e.cache == "simple"
    assert e.status == 200
    assert e.content_type == "text/html"
    assert e.body_size == len(HTML)
    assert e.response_time == "2026-11-14T09:00:00Z"
    assert e.request_time == "2026-11-14T08:59:00Z"
    assert e.server == "nginx"
    assert by["https://example.com/logo.png"].content_type == "image/png"


def test_simple_cache_extract_and_hash(tmp_path):
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://cdn.example/app.js", "body": b"console.log(1)",
         "ctype": "application/javascript", "resp_time": R},
    ])
    out = tmp_path / "bodies"
    res = analyze([str(cd)], extract_dir=str(out))
    assert res.extracted == 1
    e = res.entries[0]
    assert e.sha256 == hashlib.sha256(b"console.log(1)").hexdigest()
    saved = (out / e.saved_as).read_bytes()
    assert saved == b"console.log(1)"


def test_simple_cache_gzip_decode(tmp_path):
    raw = b"<html>" + b"y" * 2000 + b"</html>"
    gz = gzip.compress(raw)
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://example.com/page", "body": gz, "ctype": "text/html",
         "declared_length": len(gz),
         "extra_headers": ["Content-Encoding: gzip"], "resp_time": R},
    ])
    res = analyze([str(cd)], keep_bodies=True)
    e = res.entries[0]
    assert e.content_encoding == "gzip"
    assert e._body == raw
    assert e.body_size == len(raw)


def test_simple_cache_executable_flag(tmp_path):
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://dl.example/setup", "body": MZ,
         "ctype": "text/html", "resp_time": R},
    ])
    res = analyze([str(cd)], keep_bodies=True)
    n = res.entries[0].notable
    assert any("body is an executable" in x for x in n)
    assert any("content-type / body mismatch" in x for x in n)
    assert output.row(res.entries[0])["severity"] == "high"


def test_simple_cache_truncated(tmp_path):
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://example.com/big.bin", "body": b"A" * 100,
         "ctype": "application/octet-stream", "declared_length": 5000,
         "resp_time": R},
    ])
    e = analyze([str(cd)]).entries[0]
    assert e.truncated
    assert any("shorter than Content-Length" in x for x in e.notable)


def test_firefox_cache2_basic(tmp_path):
    cd = S.cache2_dir(tmp_path, [
        {"url": "https://developer.mozilla.org/style.css",
         "body": b"body{margin:0}", "ctype": "text/css", "status": 200,
         "fetch_count": 3, "last_fetched": R, "last_modified": Q,
         "extra_headers": ["Server: Apache"]},
    ])
    res = analyze([str(cd)])
    e = res.entries[0]
    assert e.cache == "cache2" and e.browser == "Firefox"
    assert e.url == "https://developer.mozilla.org/style.css"
    assert e.content_type == "text/css"
    assert e.status == 200
    assert e.fetch_count == 3
    assert e.last_fetched == "2026-11-14T09:00:00Z"
    assert e.server == "Apache"
    assert e._body == b"" and e.body_size == len(b"body{margin:0}")


def test_firefox_cache2_extract(tmp_path):
    cd = S.cache2_dir(tmp_path, [
        {"url": "https://x.example/data.json", "body": b'{"a":1}',
         "ctype": "application/json", "last_fetched": R},
    ])
    out = tmp_path / "b"
    res = analyze([str(cd)], extract_dir=str(out))
    assert res.extracted == 1
    e = res.entries[0]
    assert (out / e.saved_as).read_bytes() == b'{"a":1}'
    assert e.sha256 == hashlib.sha256(b'{"a":1}').hexdigest()


def test_walk_both_stores(tmp_path):
    prof = tmp_path / "Users" / "a"
    S.simple_cache_dir(prof / "Chrome", [
        {"url": "https://a.example/", "body": b"a", "resp_time": R}])
    S.cache2_dir(prof / "Firefox", [
        {"url": "https://b.example/", "body": b"b", "last_fetched": R}])
    res = analyze([str(tmp_path / "Users")])
    assert res.stores == 2
    assert {e.browser for e in res.entries} == {"", "Firefox"}


def test_cli_csv_json_filters(tmp_path):
    cd = S.simple_cache_dir(tmp_path, [
        {"url": "https://x.example/a.js", "body": b"j",
         "ctype": "application/javascript", "resp_time": R},
        {"url": "https://x.example/b.css", "body": b"c",
         "ctype": "text/css", "resp_time": R},
    ])
    csv_p = tmp_path / "c.csv"
    js_p = tmp_path / "c.json"
    rc = main([str(cd), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 2

    main([str(cd), "--content-type", "javascript", "--json", str(js_p), "-q"])
    assert len(json.loads(js_p.read_text())) == 1

    main([str(cd), "--grep", r"\.css$", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["url"].endswith("b.css")


def test_not_a_cache(tmp_path):
    p = tmp_path / "junk_0"
    p.write_bytes(b"nope")
    assert simplecache.parse_entry(str(p)) is None


def test_csv_injection_guard():
    assert output._san("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
