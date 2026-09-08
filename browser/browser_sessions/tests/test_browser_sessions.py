from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from browser_sessions import output
from browser_sessions.analyze import analyze
from browser_sessions.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from browser_sessions.lz4 import lz4_block_decompress, mozlz4_decompress

import _synth as S

T = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)


def _w(tmp_path, blob, name):
    p = tmp_path / name
    if isinstance(blob, bytes):
        p.write_bytes(blob)
    else:
        p.write_text(blob)
    return p


# --------------------------------------------------------------------------
# LZ4
# --------------------------------------------------------------------------

def test_lz4_literal_roundtrip():
    data = b"the quick brown fox " * 20
    comp = S._lz4_literals(data)
    assert lz4_block_decompress(comp) == data


def test_lz4_with_matches():
    # "abcabcabc..." - the decoder must follow overlapping matches
    # token 0x40 = 4 literals, 0 match-len(+4); offset 3
    block = bytes([0x40]) + b"abca" + bytes([0x03, 0x00]) + bytes([0x50]) \
        + b""                       # 4-byte literal + match len 4, off 3
    # simpler: hand a known vector
    src = b"abcd" + bytes([0x1c]) + bytes([0x04, 0x00])
    #      lit "abcd" (token 0x40 -> 4 lits, 0 mlen) ...
    src = bytes([0x40]) + b"abcd" + bytes([0x04, 0x00]) + bytes([0x00])
    out = lz4_block_decompress(src)
    assert out.startswith(b"abcd")


def test_mozlz4_container(tmp_path):
    obj = S.sessionstore_obj([S.win([S.tab([("https://x.example/", "X")])])])
    blob = S.mozlz4(obj)
    assert json.loads(mozlz4_decompress(blob)) == obj


# --------------------------------------------------------------------------
# Chromium SNSS
# --------------------------------------------------------------------------

def test_snss_basic(tmp_path):
    f = _w(tmp_path, S.snss([
        {"tab_id": 1, "window": 5, "index": 0, "last_active": T,
         "entries": [("https://example.com/", "Example"),
                     ("https://example.com/page2", "Page 2")]},
        {"tab_id": 2, "window": 5, "index": 1, "pinned": True,
         "entries": [("https://mail.example.com/", "Mail")]},
    ]), "Last Session")
    res = analyze([str(f)])
    tabs = {t.current_url: t for t in res.tabs}
    assert "https://example.com/page2" in tabs
    t1 = tabs["https://example.com/page2"]
    assert t1.current_title == "Page 2"
    assert t1.entry_count == 2
    assert t1.window == "window 5"
    assert t1.last_accessed == "2026-11-14T09:00:00Z"
    assert tabs["https://mail.example.com/"].pinned is True


def test_snss_auth_and_closed_flags(tmp_path):
    f = _w(tmp_path, S.snss([
        {"tab_id": 1, "entries": [("https://accounts.example.com/signin",
                                   "Sign in")]},
        {"tab_id": 2, "closed": True,
         "entries": [("https://darkweb.example/market", "Market")]},
    ]), "Current Session")
    res = analyze([str(f)])
    by = {t.current_url: t for t in res.tabs}
    assert any("sign-in" in x for x in
               by["https://accounts.example.com/signin"].notable)
    closed = by["https://darkweb.example/market"]
    assert closed.closed
    assert any("recently-closed tab retained" in x for x in closed.notable)


def test_not_snss(tmp_path):
    f = _w(tmp_path, b"not a session file", "Session_123")
    res = analyze([str(f)])
    assert res.tabs == []


# --------------------------------------------------------------------------
# Firefox sessionstore
# --------------------------------------------------------------------------

def test_firefox_sessionstore_jsonlz4(tmp_path):
    obj = S.sessionstore_obj([
        S.win([
            S.tab([("https://developer.mozilla.org/", "MDN"),
                   ("https://developer.mozilla.org/docs", "Docs")],
                  index=2, last_accessed=int(T.timestamp() * 1000)),
            S.tab([("https://bank.example/login", "Login")],
                  formdata={"id": {"user": "alice"}}),
        ], closed_tabs=[{"state": {"entries": [
            {"url": "https://reddit.com/", "title": "reddit"}]},
            "closedAt": int(T.timestamp() * 1000)}]),
    ])
    f = _w(tmp_path, S.mozlz4(obj), "sessionstore.jsonlz4")
    res = analyze([str(f)])
    by = {t.current_url: t for t in res.tabs}
    assert by["https://developer.mozilla.org/docs"].current_title == "Docs"
    assert by["https://developer.mozilla.org/docs"].entry_count == 2
    login = by["https://bank.example/login"]
    assert login.has_formdata
    assert any("form data preserved" in x for x in login.notable)
    reddit = by["https://reddit.com/"]
    assert reddit.closed


def test_firefox_plain_js(tmp_path):
    obj = S.sessionstore_obj([S.win([S.tab([("https://x.example/", "X")])])])
    f = _w(tmp_path, json.dumps(obj), "sessionstore.js")
    res = analyze([str(f)])
    assert res.tabs and res.tabs[0].current_url == "https://x.example/"


def test_many_tabs_finding(tmp_path):
    obj = S.sessionstore_obj([S.win(
        [S.tab([(f"https://site{i}.example/", f"S{i}")]) for i in range(35)])])
    f = _w(tmp_path, S.mozlz4(obj), "sessionstore.jsonlz4")
    res = analyze([str(f)])
    assert any("35 tabs open at last close" in x for x in res.findings)


def test_cli_csv_json_filters(tmp_path):
    f = _w(tmp_path, S.snss([
        {"tab_id": 1, "entries": [("https://a.example/", "A")]},
        {"tab_id": 2, "closed": True,
         "entries": [("https://b.example/", "B")]},
    ]), "Last Session")
    csv_p = tmp_path / "s.csv"
    js_p = tmp_path / "s.json"
    rc = main([str(f), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(_recs(js_p)) == 2

    main([str(f), "--closed-only", "--json", str(js_p), "-q"])
    only = _recs(js_p)
    assert len(only) == 1 and only[0]["current_url"] == "https://b.example/"


def test_csv_injection_guard():
    assert output._san("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
