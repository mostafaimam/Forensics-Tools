from __future__ import annotations

import json

import pytest

from utilities_strings.strings import scan, iter_strings
from utilities_strings.cli import main


def _blob(tmp_path):
    parts = [
        b"\x00\x01\x02short",                     # too short at min-len 6
        b"a normal ascii string here\x00",
        "unicode LE string".encode("utf-16-le"),
        "unicode BE string".encode("utf-16-be"),
        b"connect to http://evil.example/c2 now\x00",
        b"user@corp.example sent mail\x00",
        b"powershell -enc SQBFAFgAIAAoAG4AZQB3AA==\x00",
        b"card 4111111111111111 stored\x00",       # valid Luhn
        b"card 4111111111111112 invalid\x00",      # bad Luhn
        b"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe\x00",
        b"sekurlsa::logonpasswords\x00",
    ]
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x00".join(parts))
    return p


def test_extract_encodings(tmp_path):
    p = _blob(tmp_path)
    hits = list(iter_strings(str(p), min_len=6,
                             encodings=("ascii", "utf-16le", "utf-16be")))
    texts = [h.text for h in hits]
    assert "a normal ascii string here" in texts
    assert "unicode LE string" in texts
    assert "unicode BE string" in texts
    assert "short" not in texts
    encs = {h.encoding for h in hits}
    assert encs >= {"ascii", "utf-16le", "utf-16be"}


def test_classification(tmp_path):
    p = _blob(tmp_path)
    got = {}
    for h in scan(str(p), min_len=6, classified_only=True):
        got.setdefault(h.category, []).append(h.match)
    assert any("evil.example/c2" in m for m in got.get("url", []))
    assert "user@corp.example" in got.get("email", [])
    assert got.get("powershell")
    assert "4111111111111111" in got.get("credit_card", [])
    assert "4111111111111112" not in got.get("credit_card", [])   # Luhn
    assert got.get("win_path")
    assert got.get("mimikatz")


def test_category_filter(tmp_path):
    p = _blob(tmp_path)
    urls = list(scan(str(p), min_len=6, categories=["url"]))
    assert urls and all(h.category == "url" for h in urls)


def test_boundary_string(tmp_path):
    # a string that would straddle an 8 MiB read boundary
    p = tmp_path / "big.bin"
    filler = b"\x00" * ((8 << 20) - 10)
    p.write_bytes(filler + b"BOUNDARYCROSSINGSTRING" + b"\x00" * 32)
    texts = [h.text for h in iter_strings(str(p), min_len=6)]
    assert "BOUNDARYCROSSINGSTRING" in texts


def test_cli_csv_json(tmp_path):
    p = _blob(tmp_path)
    csv_p = tmp_path / "s.csv"
    js_p = tmp_path / "s.json"
    rc = main([str(p), "--min-len", "6", "--category", "url,email,mimikatz",
               "--csv", str(csv_p), "--json", str(js_p), "-q", "--hex"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert rows and all(r["category"] in ("url", "email", "mimikatz")
                        for r in rows)
    assert all(str(r["offset"]).startswith("0x") for r in rows)


def test_list_patterns(capsys):
    rc = main(["--list-patterns"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "url" in out and "mimikatz" in out


def test_csv_injection_guard():
    from utilities_strings.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
