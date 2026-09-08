"""Mutation-fuzz the Simple Cache and cache2 entry parsers."""

from __future__ import annotations

from datetime import datetime, timezone

from browser_cache import cache2, fuzzlib, simplecache

import _synth as S

R = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)


def test_fuzz_simple_cache_entry(tmp_path):
    seed = tmp_path / "seed_0"
    S.simple_entry(seed, url="https://example.com/a.html",
                   body=b"<html>" + b"x" * 500 + b"</html>",
                   status=200, ctype="text/html", req_time=R, resp_time=R,
                   extra_headers=["Server: nginx", "Content-Encoding: gzip"])
    data = seed.read_bytes()
    fuzzlib.fuzz(simplecache.parse_entry, [data], iterations=500, seed=7,
                 accepts="path", tmp_path=tmp_path)


def test_fuzz_cache2_entry(tmp_path):
    seed = tmp_path / "seed"
    S.cache2_entry(seed, url="https://developer.mozilla.org/x.css",
                   body=b"body{margin:0}" * 40, ctype="text/css", status=200,
                   fetch_count=3, last_fetched=R, last_modified=R)
    data = seed.read_bytes()
    fuzzlib.fuzz(cache2.parse_entry, [data], iterations=500, seed=8,
                 accepts="path", tmp_path=tmp_path)
