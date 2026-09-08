from __future__ import annotations

import json

import pytest

from network_flows import output, records
from network_flows.analyze import analyze
from network_flows.cli import main

import _synth as S


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d


def _w(tmp_path, blob, name):
    p = tmp_path / name
    p.write_bytes(blob)
    return p


def _conv(res, server_ip):
    return next(c for c in res.conversations if c.server == server_ip)


def test_netflow5(tmp_path):
    blob = S.nf5([
        {"src": "10.0.0.5", "dst": "93.184.216.34", "sport": 51000,
         "dport": 443, "proto": 6, "pkts": 20, "octets": 8000,
         "first_ago": 30, "last_ago": 0, "tcp_flags": 0x1b},
        {"src": "93.184.216.34", "dst": "10.0.0.5", "sport": 443,
         "dport": 51000, "proto": 6, "pkts": 30, "octets": 40000},
    ])
    p = _w(tmp_path, blob, "e.nf5")
    res = analyze([str(p)])
    assert res.flows == 2
    c = _conv(res, "93.184.216.34")
    assert c.server == "93.184.216.34" and c.server_port == 443
    assert c.total_bytes == 48000
    assert c.total_packets == 50
    assert "S" in output.row(c)["tcp_flags"]


def test_netflow9_with_template(tmp_path):
    blob = S.nf9([
        {"src": "10.0.0.9", "dst": "1.1.1.1", "sport": 40000, "dport": 53,
         "proto": 17, "pkts": 2, "octets": 200},
    ])
    p = _w(tmp_path, blob, "e.nf9")
    res = analyze([str(p)])
    assert res.kinds.get("netflow9") == 1
    c = _conv(res, "1.1.1.1")
    assert c.server == "1.1.1.1" and c.server_port == 53 and c.proto == 17
    assert c.total_bytes == 200


def test_netflow9_template_reuse_across_messages(tmp_path):
    m1 = S.nf9([{"src": "10.0.0.9", "dst": "8.8.8.8", "dport": 53,
                 "proto": 17, "octets": 100}], with_template=True)
    m2 = S.nf9([{"src": "10.0.0.9", "dst": "8.8.4.4", "dport": 53,
                 "proto": 17, "octets": 120}], with_template=False)
    p = _w(tmp_path, m1 + m2, "two.nf9")
    res = analyze([str(p)])
    assert res.flows == 2
    assert {c.server for c in res.conversations} == {"8.8.8.8", "8.8.4.4"}


def test_ipfix_with_template(tmp_path):
    blob = S.ipfix([
        {"src": "10.0.0.5", "dst": "140.82.112.3", "sport": 52000,
         "dport": 443, "proto": 6, "pkts": 10, "octets": 3000,
         "first_ms": S.BASE * 1000, "last_ms": S.BASE * 1000 + 12000},
    ])
    p = _w(tmp_path, blob, "e.ipfix")
    res = analyze([str(p)])
    assert res.kinds.get("ipfix") == 1
    c = _conv(res, "140.82.112.3")
    assert round(c.duration) == 12
    assert c.total_bytes == 3000


def test_sflow_flow_sample(tmp_path):
    blob = S.sflow([
        {"src": "10.0.0.50", "dst": "185.43.99.42", "sport": 44000,
         "dport": 4444, "frame_len": 1500},
    ], rate=1000)
    p = _w(tmp_path, blob, "e.sflow")
    res = analyze([str(p)])
    assert res.kinds.get("sflow") == 1
    c = res.conversations[0]
    assert c.server in ("185.43.99.42", "10.0.0.50")
    assert c.total_bytes == 1500 * 1000          # scaled by sampling rate


def test_large_transfer_and_outbound_heavy_flags(tmp_path):
    blob = S.nf5([
        {"src": "10.0.0.50", "dst": "45.9.148.200", "sport": 51000,
         "dport": 443, "proto": 6, "pkts": 90000, "octets": 130 * 1024 * 1024,
         "first_ago": 600, "last_ago": 0},
        {"src": "45.9.148.200", "dst": "10.0.0.50", "sport": 443,
         "dport": 51000, "proto": 6, "pkts": 2000, "octets": 200 * 1024},
    ])
    p = _w(tmp_path, blob, "exfil.nf5")
    c = _conv(analyze([str(p)]), "45.9.148.200")
    joined = " ".join(c.notable)
    assert "large transfer" in joined
    assert "outbound-heavy" in joined
    assert output.row(c)["severity"] == "high"


def test_scan_fanout_flag(tmp_path):
    recs = [{"src": "10.0.0.66", "dst": f"10.0.{i // 254}.{i % 254 + 1}",
             "sport": 40000 + i, "dport": 445, "proto": 6, "pkts": 1,
             "octets": 40, "tcp_flags": 0x02} for i in range(40)]
    p = _w(tmp_path, S.nf5(recs), "scan.nf5")
    res = analyze([str(p)])
    flagged = [c for c in res.conversations
               if any("scan" in x for x in c.notable)]
    assert flagged
    assert any("port probe" in " ".join(c.notable) or "SYN with no ACK"
               in " ".join(c.notable) for c in res.conversations)


def test_beacon_flag(tmp_path):
    recs = []
    for i in range(8):
        t_ago = 600 - i * 60          # every 60 s
        recs.append({"src": "10.0.0.50", "dst": "203.0.113.9",
                     "sport": 50000 + i, "dport": 443, "proto": 6,
                     "pkts": 6, "octets": 820, "first_ago": t_ago,
                     "last_ago": t_ago - 1})
    p = _w(tmp_path, S.nf5(recs), "beacon.nf5")
    c = _conv(analyze([str(p)]), "203.0.113.9")
    assert any("beacon" in x for x in c.notable)


def test_cli_csv_json_summary_filters(tmp_path):
    blob = S.nf5([
        {"src": "10.0.0.5", "dst": "1.2.3.4", "dport": 443, "proto": 6,
         "octets": 5000, "pkts": 10},
        {"src": "10.0.0.5", "dst": "1.2.3.5", "dport": 22, "proto": 6,
         "octets": 800, "pkts": 6},
    ])
    p = _w(tmp_path, blob, "c.nf5")
    csv_p = tmp_path / "c.csv"
    js_p = tmp_path / "c.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = _recs(js_p)
    assert len(data) == 2

    main([str(p), "--port", "22", "--json", str(js_p), "-q"])
    only = _recs(js_p)
    assert len(only) == 1 and only[0]["server_port"] == 22

    main([str(p), "--host", "10.0.0.0/24", "--json", str(js_p), "-q"])
    assert len(_recs(js_p)) == 2


def test_not_a_flow_file(tmp_path):
    p = _w(tmp_path, b"\x00\x01\x02\x03not flow data", "x.bin")
    res = analyze([str(p)])
    assert res.errors and "not a NetFlow" in res.errors[0]


def test_provenance_manifest_and_columns(tmp_path):
    import json as _j
    blob = S.nf5([{"src": "10.0.0.5", "dst": "1.2.3.4", "dport": 443,
                   "proto": 6, "octets": 5000, "pkts": 10}])
    p = _w(tmp_path, blob, "e.nf5")
    csv_p = tmp_path / "c.csv"
    js_p = tmp_path / "c.json"
    main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q",
          "--case-id", "IR-2026-11", "--evidence-id", "PCAP-01"])
    head = csv_p.read_bytes().decode("utf-8-sig").splitlines()[0].split(",")
    assert "evidence_source" in head and "parser_confidence" in head
    m = _j.loads((tmp_path / "c.csv.manifest.json").read_text())
    assert m["case_id"] == "IR-2026-11"
    assert len(m["inputs"][0]["sha256"]) == 64
    assert m["outputs"][0]["sha256"]
    doc = _j.loads(js_p.read_text())
    assert doc["manifest"]["evidence_id"] == "PCAP-01"
    assert doc["records"][0]["parser_confidence"] == "medium"


def test_resource_limit_rejects_big_input(tmp_path):
    p = tmp_path / "big.nf5"
    p.write_bytes(b"\x00\x00\x00\x05" + b"\x00" * 2000)
    rc = main([str(p), "-q", "--max-input-bytes", "500"])
    assert rc == 3


def test_csv_injection_guard():
    assert output._san("=1+1") == "'=1+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
