from __future__ import annotations

import json

import pytest

from network_arp import oui, output
from network_arp.analyze import analyze
from network_arp.cli import main

import _synth as S


def _w(tmp_path, content, name):
    p = tmp_path / name
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content)
    return p


def _b(res):
    return {(x.ip, x.mac): x for x in res.bindings}


def test_oui_helpers():
    assert oui.norm("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert oui.vendor("08:00:27:11:22:33") == "VirtualBox"
    assert oui.is_local("02:11:22:33:44:55") is True
    assert oui.is_local("08:00:27:11:22:33") is False


def test_dhcpd_leases(tmp_path):
    res = analyze([str(_w(tmp_path, S.DHCPD_LEASES, "dhcpd.leases"))])
    b = _b(res)
    k = ("192.168.1.50", "08:00:27:11:22:33")
    assert k in b
    assert "laptop-alice" in b[k].hostnames
    assert b[k].first is not None and b[k].last is not None
    assert res.sources["dhcpd"] >= 2


def test_windows_dhcp_audit(tmp_path):
    res = analyze([str(_w(tmp_path, S.WIN_DHCP, "DhcpSrvLog-Wed.log"))])
    b = _b(res)
    k = ("192.168.1.60", "a1:b2:c3:d4:e5:f6")
    assert k in b
    assert "phone-carol.corp" in b[k].hostnames
    assert b[k].count == 2                       # assign + renew
    assert "renew" in b[k].kinds


def test_arp_table_linux(tmp_path):
    res = analyze([str(_w(tmp_path, S.ARP_TABLE, "arp.txt"))])
    b = _b(res)
    assert ("192.168.1.1", "aa:bb:cc:00:00:01") in b
    assert ("192.168.1.99", "de:ad:be:ef:00:99") in b


def test_arp_table_windows(tmp_path):
    res = analyze([str(_w(tmp_path, S.WIN_ARP_TABLE, "winarp.txt"))])
    b = _b(res)
    assert ("192.168.1.77", "02:11:22:33:44:55") in b
    assert any("locally-administered" in x
               for x in b[("192.168.1.77", "02:11:22:33:44:55")].notable)


def test_pcap_arp_frames(tmp_path):
    frames = [
        S.arp_frame(1, "08:00:27:11:22:33", "192.168.1.50",
                    "00:00:00:00:00:00", "192.168.1.1"),
        S.arp_frame(2, "aa:bb:cc:00:00:01", "192.168.1.1",
                    "08:00:27:11:22:33", "192.168.1.50"),
        S.ip_frame("08:00:27:11:22:33", "192.168.1.50", "8.8.8.8"),
    ]
    res = analyze([str(_w(tmp_path, S.pcap(frames), "c.pcap"))])
    b = _b(res)
    assert ("192.168.1.50", "08:00:27:11:22:33") in b
    assert ("192.168.1.1", "aa:bb:cc:00:00:01") in b
    binding = b[("192.168.1.50", "08:00:27:11:22:33")]
    assert {"pcap-arp", "pcap-passive"} <= binding.sources


def test_gratuitous_arp_flagged(tmp_path):
    frames = [S.arp_frame(1, "08:00:27:11:22:33", "192.168.1.50",
                          "ff:ff:ff:ff:ff:ff", "192.168.1.50")]
    res = analyze([str(_w(tmp_path, S.pcap(frames), "g.pcap"))])
    b = list(res.bindings)[0]
    assert "gratuitous" in b.kinds
    assert any("gratuitous ARP" in x for x in b.notable)


def test_arp_spoofing_conflict(tmp_path):
    # same IP, two different MACs, overlapping in time
    frames = [
        S.arp_frame(2, "aa:bb:cc:00:00:01", "192.168.1.1",
                    "08:00:27:11:22:33", "192.168.1.50"),
        S.arp_frame(2, "de:ad:be:ef:66:66", "192.168.1.1",
                    "08:00:27:11:22:33", "192.168.1.50"),
        S.arp_frame(2, "aa:bb:cc:00:00:01", "192.168.1.1",
                    "08:00:27:11:22:33", "192.168.1.50"),
    ]
    res = analyze([str(_w(tmp_path, S.pcap(frames), "spoof.pcap"))])
    assert res.conflicts and "192.168.1.1" in res.conflicts[0]
    for b in res.bindings:
        if b.ip == "192.168.1.1":
            assert any("claimed by 2 MACs" in x for x in b.notable)
            assert output.row(b)["severity"] == "high"


def test_merge_lease_and_arp_and_conflict_detection(tmp_path):
    p1 = _w(tmp_path, S.DHCPD_LEASES, "dhcpd.leases")
    p2 = _w(tmp_path, S.ARP_TABLE, "arp.txt")
    res = analyze([str(p1), str(p2)])
    b = _b(res)
    k = ("192.168.1.50", "08:00:27:11:22:33")
    assert {"dhcpd", "arptable"} <= b[k].sources


def test_cli_csv_json_filters(tmp_path):
    p = _w(tmp_path, S.DHCPD_LEASES, "dhcpd.leases")
    csv_p = tmp_path / "m.csv"
    js_p = tmp_path / "m.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 2

    main([str(p), "--ip", "192.168.1.51", "--json", str(js_p), "-q"])
    only = json.loads(js_p.read_text())
    assert len(only) == 1 and only[0]["mac"] == "00:0c:29:aa:bb:cc"

    main([str(p), "--host", "bob", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["ip"] == "192.168.1.51"


def test_unrecognised_source(tmp_path):
    res = analyze([str(_w(tmp_path, "hello world\n", "x.txt"))])
    assert res.errors and "unrecognised" in res.errors[0]


def test_csv_injection_guard():
    assert output._san("=x") == "'=x"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
