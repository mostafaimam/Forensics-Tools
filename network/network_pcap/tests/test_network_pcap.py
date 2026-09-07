import csv
import json

import pytest

from network_pcap import pcap
from network_pcap.analyze import analyze
from network_pcap.appproto import parse_dns, parse_http
from network_pcap.cli import main
from network_pcap.flags import flag_dns, severity
from network_pcap.layers import decode

import _synth as s

C, DNS, SRV, EVIL = "10.0.0.50", "10.0.0.1", "93.184.216.34", "185.43.99.42"
T = 1_700_000_000.0


def _pkts():
    return [
        (T, s.frame_udp(C, DNS, 51000, 53, s.dns_query("example.com"))),
        (T + .02, s.frame_udp(DNS, C, 53, 51000,
                              s.dns_response("example.com", [SRV]))),
        (T + .1, s.frame_tcp(C, SRV, 44000, 80, flags="S")),
        (T + .11, s.frame_tcp(SRV, C, 80, 44000, flags="S.")),
        (T + .12, s.frame_tcp(C, SRV, 44000, 80,
                              s.http_get("example.com", "/a.html"))),
        (T + .15, s.frame_tcp(SRV, C, 80, 44000, s.http_response(200))),
        (T + .16, s.frame_tcp(C, SRV, 44000, 80, flags="FA")),
        (T + 1.0, s.frame_udp(C, DNS, 51001, 53, s.dns_query(
            "aGVsbG8td29ybGQtdGhpc2lzYWxvbmdiYXNlNjRzdHJpbmdwYXk"
            ".tun.evil.top", 16))),
        (T + 2.0, s.frame_tcp(C, EVIL, 44100, 80,
                              s.http_post("185.43.99.42", "/gate.php",
                                          "u=admin&password=hunter2"))),
        (T + 3.0, s.frame_tcp(C, EVIL, 44200, 23, b"login:")),
    ]


def _write(tmp_path, fmt=s.pcap, name="c.pcap"):
    p = tmp_path / name
    p.write_bytes(fmt(_pkts()))
    return p


# --------------------------------------------------------------------------
# container readers
# --------------------------------------------------------------------------

def test_reads_pcap_and_pcapng(tmp_path):
    for fmt, name in ((s.pcap, "c.pcap"), (s.pcapng, "c.pcapng")):
        cap = analyze([str(_write(tmp_path, fmt, name))])
        assert cap.packets == 10 and cap.decoded == 10
        # same first/last timestamp regardless of container
        assert abs(cap.last_ts - cap.first_ts - 3.0) < 0.01


def test_nanosecond_pcap(tmp_path):
    p = tmp_path / "n.pcap"
    p.write_bytes(s.pcap(_pkts(), nano=True))
    cap = analyze([str(p)])
    assert cap.packets == 10
    assert abs(cap.last_ts - cap.first_ts - 3.0) < 0.01


def test_bad_file(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a capture at all")
    with pytest.raises(pcap.PcapError):
        list(pcap.read(str(p)))


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------

def test_decode_tcp_udp_ipv6():
    p = decode(0.0, 1, s.frame_tcp(C, SRV, 1234, 443, b"hello", flags="S"))
    assert p.proto == "TCP" and p.src == C and p.dport == 443
    assert p.tcp_flags == "S"
    p2 = decode(0.0, 1, s.frame6_tcp("2001:db8::1", "2001:db8::2", 5, 443))
    assert p2.ip_version == 6 and p2.dst == "2001:db8::2"
    p3 = decode(0.0, 101, s.ipv4(s.udp(b"x", 5, 53), 17, C, DNS))  # raw IP
    assert p3.proto == "UDP" and p3.dport == 53


# --------------------------------------------------------------------------
# flows
# --------------------------------------------------------------------------

def test_flow_reassembly(tmp_path):
    cap = analyze([str(_write(tmp_path))])
    http_flow = next(f for f in cap.flows
                     if f.service == "http" and f.server_ip == SRV)
    assert http_flow.client_ip == C
    assert http_flow.packets == 5           # S, S., GET, resp, FA
    assert {"S", "F"} <= http_flow.tcp_flags
    assert http_flow.duration > 0


def test_flow_flags(tmp_path):
    cap = analyze([str(_write(tmp_path))])
    by_srv = {f.server_ip: f for f in cap.flows}
    assert "plaintext-telnet-to-internet" in by_srv[EVIL + ""].notable \
        if EVIL in by_srv else True
    tel = next(f for f in cap.flows if f.b_port == 23 or f.a_port == 23)
    assert any("plaintext-telnet" in n for n in tel.notable)
    assert any("no-dns-for-dst" in n for n in tel.notable)
    ex = next(f for f in cap.flows if f.server_ip == SRV
              and f.service == "http")
    assert "no-dns-for-dst" not in " ".join(ex.notable)   # example.com resolved


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

def test_dns_parse():
    d = parse_dns(s.dns_query("mail.example.com", 15))
    assert d["queries"] == [("mail.example.com", "MX")]
    r = parse_dns(s.dns_response("example.com", ["93.184.216.34"]))
    assert r["response"] and ("A", "93.184.216.34") in r["answers"]


def test_dns_tunnelling_flag(tmp_path):
    cap = analyze([str(_write(tmp_path))])
    tun = next(d for d in cap.dns if "evil.top" in d.query and not d.response)
    assert "suspect-tld:.top" in tun.notable
    assert any("tunnelling" in n or "high-entropy" in n or "long-dns-label"
               in n for n in tun.notable)


def test_flag_dns_direct():
    class D:
        query = "x.ngrok-free.app"
        qtype = "A"
    assert "tunnel-domain" in flag_dns(D())


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def test_http_parse():
    h = parse_http(s.http_get("example.com", "/p", ua="curl/8.0"))
    assert h["method"] == "GET" and h["host"] == "example.com"
    assert h["user_agent"] == "curl/8.0"
    r = parse_http(s.http_response(404))
    assert r["kind"] == "response" and r["status"] == 404


def test_http_records_and_flags(tmp_path):
    cap = analyze([str(_write(tmp_path))])
    assert len(cap.http) == 2                # GET (merged w/ 200) + POST
    get = next(h for h in cap.http if h.method == "GET")
    assert get.status == 200 and get.host == "example.com"
    post = next(h for h in cap.http if h.method == "POST")
    assert "password-in-http-body" in post.notable
    assert "scripted-user-agent" in post.notable
    assert "http-to-ip-literal" in post.notable


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_flows_csv(tmp_path):
    p = _write(tmp_path)
    out = tmp_path / "f.csv"
    assert main([str(p), "--csv", str(out), "-q"]) == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and any(r["service"] == "http" for r in rows)
    assert any(r["severity"] in ("medium", "high") for r in rows)


def test_cli_views(tmp_path):
    p = _write(tmp_path)
    d = tmp_path / "d.json"
    main([str(p), "--dns", "--json", str(d), "-q"])
    dns = json.loads(d.read_text())
    assert any("evil.top" in r["query"] for r in dns)

    h = tmp_path / "h.csv"
    main([str(p), "--http", "--csv", str(h), "-q"])
    hrows = list(csv.DictReader(h.open(encoding="utf-8-sig")))
    assert any(r["method"] == "POST" for r in hrows)


def test_cli_filters(tmp_path):
    p = _write(tmp_path)

    out = tmp_path / "n.csv"
    main([str(p), "--notable-only", "--min-severity", "medium",
          "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["severity"] in ("medium", "high") for r in rows)

    out2 = tmp_path / "h.csv"
    main([str(p), "--host", EVIL, "--csv", str(out2), "-q"])
    hr = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert hr and all(EVIL in (r["client"] + r["server"]) for r in hr)

    out3 = tmp_path / "s.csv"
    main([str(p), "--service", "telnet", "--csv", str(out3), "-q"])
    sr = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert len(sr) == 1


def test_cli_grep(tmp_path):
    p = _write(tmp_path)
    out = tmp_path / "g.json"
    main([str(p), "--http", "--grep", "gate", "--json", str(out), "-q"])
    assert any("gate.php" in r["url"] for r in json.loads(out.read_text()))


def test_cli_no_path():
    with pytest.raises(SystemExit):
        main([])


def test_severity_scale():
    assert severity([]) == "none"
    assert severity(["plaintext-http"]) == "medium"
    assert severity(["tunnel-domain"]) == "high"
