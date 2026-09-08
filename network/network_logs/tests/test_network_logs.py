from __future__ import annotations

import json
import textwrap

import pytest

from network_logs import formats, output
from network_logs.analyze import analyze
from network_logs.cli import main

IPTABLES = textwrap.dedent("""\
    Nov 14 09:12:01 gw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=185.43.99.42 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=53122 DPT=22 WINDOW=1024 SYN
    Nov 14 09:12:02 gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.43.99.42 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=53123 DPT=23
    Nov 14 09:12:03 gw kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.5 DST=93.184.216.34 LEN=52 PROTO=TCP SPT=44001 DPT=443
""")

WINFW = textwrap.dedent("""\
    #Version: 1.5
    #Software: Microsoft Windows Firewall
    #Time Format: Local
    #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid

    2026-11-14 09:20:00 DROP TCP 45.9.148.200 10.0.0.9 40001 445 48 S 0 0 0 - - - RECEIVE -
    2026-11-14 09:20:05 ALLOW TCP 10.0.0.9 20.190.159.23 51000 443 0 - - - - - - - SEND -
""")

SQUID = ("1699999990.100 120 10.0.0.5 TCP_MISS/200 68000000 GET "
         "http://cdn.example.com/big.bin - HIER_DIRECT/93.184.216.34 "
         "application/octet-stream\n"
         "1699999991.200 15 10.0.0.5 TCP_DENIED/403 3921 GET "
         "http://blocked.example.com/ - HIER_NONE/- text/html\n"
         "1699999992.300 40 10.0.0.5 TCP_MISS/200 800 GET "
         "http://user:secret@45.9.148.200/panel - HIER_DIRECT/45.9.148.200 "
         "text/html\n")

ZEEK = textwrap.dedent("""\
    #separator \\x09
    #path\tconn
    #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state
    1699999000.0\tC1\t10.0.0.5\t44010\t203.0.113.9\t4444\ttcp\t-\t3.0\t500\t20\tSF
    1699999001.0\tC2\t45.9.148.200\t5000\t10.0.0.9\t3389\ttcp\t-\t0.0\t0\t0\tREJ
""")

SURICATA = (
    '{"timestamp":"2026-11-14T09:30:00.000000+0000","event_type":"alert",'
    '"src_ip":"185.43.99.42","src_port":5555,"dest_ip":"10.0.0.5",'
    '"dest_port":445,"proto":"TCP","alert":{"signature_id":2001,'
    '"signature":"ET EXPLOIT SMB attempt","category":"Attempted Admin",'
    '"severity":1}}\n'
    '{"timestamp":"2026-11-14T09:30:05.000000+0000","event_type":"dns",'
    '"src_ip":"10.0.0.5","dest_ip":"1.1.1.1","proto":"UDP",'
    '"dns":{"rrname":"evil.example.top"}}\n')


def _w(tmp_path, text, name):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_iptables(tmp_path):
    res = analyze([str(_w(tmp_path, IPTABLES, "ufw.log"))])
    assert res.formats["iptables"] == 3
    deny = [e for e in res.events if e.action == "deny"]
    assert len(deny) == 2 and deny[0].dport == 22
    assert any("blocked inbound" in x for e in deny for x in e.notable)


def test_winfw(tmp_path):
    res = analyze([str(_w(tmp_path, WINFW, "pfirewall.log"))])
    assert res.formats["winfw"] == 2
    e = res.events[0]
    assert e.action == "drop" and e.dport == 445 and e.src == "45.9.148.200"


def test_squid(tmp_path):
    res = analyze([str(_w(tmp_path, SQUID, "access.log"))])
    assert res.formats["squid"] == 3
    big, denied, creds = res.events
    assert "large proxy transfer" in ";".join(big.notable)
    assert denied.action == "deny"
    assert any("credentials embedded" in x for x in creds.notable)
    assert any("raw-IP host" in x for x in creds.notable)


def test_zeek_conn(tmp_path):
    res = analyze([str(_w(tmp_path, ZEEK, "conn.log"))])
    assert res.formats["zeek"] == 2
    c2 = [e for e in res.events if e.dst == "10.0.0.9"][0]
    assert c2.action == "deny" and c2.dport == 3389
    abused = [e for e in res.events if e.dport == 4444][0]
    assert any("commonly-abused port" in x for x in abused.notable)


def test_suricata_eve(tmp_path):
    res = analyze([str(_w(tmp_path, SURICATA, "eve.json"))])
    assert res.formats["suricata"] == 2
    alert = [e for e in res.events if e.action == "alert"][0]
    assert alert.severity == "1"
    assert any("IDS alert (severity 1)" in x for x in alert.notable)
    assert output.row(alert)["sev_flag"] == "high"
    dns = [e for e in res.events if e.signature == "dns"][0]
    assert dns.host == "evil.example.top"


def test_blocked_burst_finding(tmp_path):
    lines = []
    for i in range(30):
        lines.append(f"Nov 14 10:00:{i:02d} gw kernel: [UFW BLOCK] IN=eth0 "
                     f"OUT= SRC=203.0.113.66 DST=10.0.0.5 LEN=40 PROTO=TCP "
                     f"SPT={40000 + i} DPT={20 + i}")
    res = analyze([str(_w(tmp_path, "\n".join(lines), "ufw.log"))])
    assert any("blocked events" in f and "203.0.113.66" in f
               for f in res.findings)
    assert any("blocked-event burst" in x
               for e in res.events for x in e.notable)


def test_multi_format_merge_and_sort(tmp_path):
    p1 = _w(tmp_path, ZEEK, "conn.log")
    p2 = _w(tmp_path, SURICATA, "eve.json")
    res = analyze([str(p1), str(p2)])
    assert set(res.formats) == {"zeek", "suricata"}
    ts = [e.ts for e in res.events if e.ts]
    assert ts == sorted(ts)


def test_cli_csv_json_filters(tmp_path):
    p = _w(tmp_path, IPTABLES, "ufw.log")
    csv_p = tmp_path / "e.csv"
    js_p = tmp_path / "e.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 3

    main([str(p), "--action", "deny", "--json", str(js_p), "-q"])
    assert len(json.loads(js_p.read_text())) == 2

    main([str(p), "--port", "443", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["dport"] == 443


def test_unrecognised_format(tmp_path):
    res = analyze([str(_w(tmp_path, "just some random text\nnothing here\n",
                          "x.log"))])
    assert res.errors and "unrecognised" in res.errors[0]


def test_csv_injection_guard():
    assert output._san("=cmd") == "'=cmd"
    assert output._san("GET /x") == "GET /x"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
