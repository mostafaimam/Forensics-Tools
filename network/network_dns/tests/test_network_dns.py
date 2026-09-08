from __future__ import annotations

import base64
import json

import pytest

from network_dns import dnsmsg, output
from network_dns.analyze import analyze
from network_dns.cli import main

import _synth as S


def _recs(path):
    d = json.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d


def _w(tmp_path, packets, name="c.pcap"):
    p = tmp_path / name
    p.write_bytes(S.pcap(packets))
    return p


def _names(res):
    return {n.qname: n for n in res.names}


def test_dnsmsg_roundtrip():
    m = dnsmsg.parse(S.dns("example.com", "A", response=True,
                           answers=[("A", "93.184.216.34", 300)]))
    assert m.is_response and m.qname == "example.com" and m.qtype == "A"
    assert m.answers[0].value == "93.184.216.34" and m.answers[0].ttl == 300


def test_basic_query_response(tmp_path):
    cap = _w(tmp_path, [
        S.q("example.com"),
        S.r("example.com", answers=[("A", "93.184.216.34", 300),
                                    ("A", "93.184.216.35", 300)]),
    ])
    res = analyze([str(cap)])
    n = _names(res)["example.com"]
    assert n.queries == 1 and n.responses == 1
    assert n.ips == {"93.184.216.34", "93.184.216.35"}
    assert output.row(n)["severity"] == "none"


def test_cname_chain(tmp_path):
    cap = _w(tmp_path, [
        S.q("www.example.com"),
        S.r("www.example.com", answers=[("CNAME", "example.com", 300)]),
    ])
    n = _names(analyze([str(cap)]))["www.example.com"]
    assert "example.com" in n.cnames


def test_nxdomain_burst_flagged(tmp_path):
    pk = []
    for i in range(6):
        pk += [S.q(f"bad{i}.example.com", tid=i),
               S.r(f"bad{i}.example.com", rcode=3, tid=i)]
    # same name repeated is what the flag counts - use one name
    pk = []
    for i in range(6):
        pk += [S.q("gone.example.com", tid=i),
               S.r("gone.example.com", rcode=3, tid=i)]
    cap = _w(tmp_path, pk)
    n = _names(analyze([str(cap)]))["gone.example.com"]
    assert n.nxdomain == 6
    assert any("NXDOMAIN" in x for x in n.notable)


def test_tunnelling_hex_label(tmp_path):
    label = "deadbeefcafe1234567890ab"
    cap = _w(tmp_path, [S.q(f"{label}.tunnel.example.net", "TXT")])
    n = _names(analyze([str(cap)]))[f"{label}.tunnel.example.net"]
    assert any("encoded left-most label" in x or "high-entropy" in x
               for x in n.notable)
    assert output.row(n)["severity"] == "high"


def test_large_txt_flagged(tmp_path):
    big = "v=" + "A" * 300
    cap = _w(tmp_path, [
        S.q("data.example.com", "TXT"),
        S.r("data.example.com", "TXT", answers=[("TXT", big, 60)]),
    ])
    n = _names(analyze([str(cap)]))["data.example.com"]
    assert any("large TXT" in x for x in n.notable)


def test_null_record_flagged(tmp_path):
    cap = _w(tmp_path, [
        S.q("c2.example.com", "NULL"),
        S.r("c2.example.com", "NULL", answers=[("NULL", "0badc0de", 0)]),
    ])
    n = _names(analyze([str(cap)]))["c2.example.com"]
    assert any("NULL record" in x for x in n.notable)


def test_zone_transfer_over_tcp(tmp_path):
    cap = _w(tmp_path, [S.tcp_dns("example.com", "AXFR")])
    res = analyze([str(cap)])
    n = _names(res)["example.com"]
    assert "AXFR" in n.qtypes
    assert any("zone-transfer" in x for x in n.notable)


def test_fast_flux(tmp_path):
    ans = [("A", f"45.9.{i}.{i + 1}", 120) for i in range(10)]
    cap = _w(tmp_path, [
        S.q("flux.example.top"),
        S.r("flux.example.top", answers=ans),
    ])
    n = _names(analyze([str(cap)]))["flux.example.top"]
    assert any("fast-flux" in x for x in n.notable)


def test_hosts_file(tmp_path):
    h = tmp_path / "hosts"
    h.write_text("127.0.0.1 localhost\n"
                 "10.0.0.9 updates.example.com  updates\n"
                 "# a comment\n"
                 "0.0.0.0 ads.tracker.net\n")
    res = analyze([str(h)])
    n = _names(res)
    assert n["updates.example.com"].static_ips == {"10.0.0.9"}
    assert any("hosts-file override" in x
               for x in n["updates.example.com"].notable)
    assert "hosts" in res.sources


def test_displaydns_text(tmp_path):
    txt = tmp_path / "displaydns.txt"
    txt.write_text(
        "\n"
        "    example.com\n"
        "    ----------------------------------------\n"
        "    Record Name . . . . . : example.com\n"
        "    Record Type . . . . . : 1\n"
        "    Time To Live  . . . . : 55\n"
        "    Data Length . . . . . : 4\n"
        "    Section . . . . . . . : Answer\n"
        "    A (Host) Record . . . : 93.184.216.34\n"
        "\n"
        "    evil.dyndns.org\n"
        "    ----------------------------------------\n"
        "    Record Name . . . . . : evil.dyndns.org\n"
        "    Record Type . . . . . : 1\n"
        "    Time To Live  . . . . : 5\n"
        "    Section . . . . . . . : Answer\n"
        "    A (Host) Record . . . : 185.43.99.42\n"
    )
    res = analyze([str(txt)])
    n = _names(res)
    assert "example.com" in n
    assert "93.184.216.34" in n["example.com"].ips
    assert res.sources.get("displaydns", 0) >= 2


def test_hosts_override_differs_from_dns(tmp_path):
    cap = _w(tmp_path, [
        S.q("bank.example.com"),
        S.r("bank.example.com", answers=[("A", "203.0.113.10", 300)]),
    ])
    h = tmp_path / "hosts"
    h.write_text("185.43.99.42 bank.example.com\n")
    n = _names(analyze([str(cap), str(h)]))["bank.example.com"]
    assert any("differs from DNS" in x for x in n.notable)
    assert output.row(n)["severity"] == "high"


def test_cli_csv_json_and_filters(tmp_path):
    cap = _w(tmp_path, [
        S.q("good.example.com"),
        S.r("good.example.com", answers=[("A", "1.2.3.4", 3600)]),
        S.q("aaaaaaaaaaaaaaaaaaaaaaaa.evil.top", "TXT"),
    ])
    csv_p = tmp_path / "n.csv"
    js_p = tmp_path / "n.json"
    rc = main([str(cap), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    raw = csv_p.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    data = _recs(js_p)
    assert len(data) == 2

    main([str(cap), "--notable-only", "--json", str(js_p), "-q"])
    only = _recs(js_p)
    assert len(only) == 1 and only[0]["qname"].endswith("evil.top")

    main([str(cap), "--grep", r"good\.", "--json", str(js_p), "-q"])
    assert _recs(js_p)[0]["qname"] == "good.example.com"


def test_provenance_manifest_and_columns(tmp_path):
    cap = _w(tmp_path, [
        S.q("good.example.com"),
        S.r("good.example.com", answers=[("A", "1.2.3.4", 3600)]),
    ])
    csv_p = tmp_path / "n.csv"
    js_p = tmp_path / "n.json"
    main([str(cap), "--csv", str(csv_p), "--json", str(js_p), "-q",
          "--case-id", "CASE-7", "--examiner", "A. Nalyst",
          "--evidence-id", "EV-3"])
    # CSV gains provenance columns
    head = csv_p.read_bytes().decode("utf-8-sig").splitlines()[0].split(",")
    for col in ("evidence_source", "parser_confidence", "tz_provenance",
                "case_id", "evidence_id"):
        assert col in head
    # CSV manifest sidecar
    m = json.loads((tmp_path / "n.csv.manifest.json").read_text())
    assert m["case_id"] == "CASE-7" and m["examiner"] == "A. Nalyst"
    assert m["inputs"][0]["path"].endswith("c.pcap")
    assert len(m["inputs"][0]["sha256"]) == 64
    assert m["outputs"][0]["sha256"]                       # output hashed
    # JSON manifest envelope + per-row provenance
    doc = json.loads(js_p.read_text())
    assert doc["manifest"]["evidence_id"] == "EV-3"
    assert doc["records"][0]["parser_confidence"] == "medium"
    assert doc["records"][0]["tz_provenance"] == "utc-native"


def test_no_provenance_flag(tmp_path):
    cap = _w(tmp_path, [S.q("x.example.com")])
    js_p = tmp_path / "n.json"
    main([str(cap), "--json", str(js_p), "-q", "--no-provenance"])
    doc = json.loads(js_p.read_text())
    assert "manifest" not in doc
    assert not (tmp_path / "n.json.manifest.json").exists()


def test_csv_injection_guard():
    assert output._san("=x") == "'=x"
    assert output._san("ok") == "ok"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
