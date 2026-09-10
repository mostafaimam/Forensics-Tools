from __future__ import annotations

import json

import pytest

from linux_networkmgr.collect import collect
from linux_networkmgr.cli import main

import _synth as S


def _items(tmp_path):
    S.build_tree(tmp_path)
    return {(i.kind, i.name): i for i in collect(str(tmp_path)).items}


def test_nm_wifi_psk(tmp_path):
    it = _items(tmp_path)[("nm-connection", "HomeWiFi")]
    assert it.conn_type == "wifi"
    assert it.ssid == "HomeWiFi"
    assert it.security == "wpa-psk"
    assert it.secret_stored == "psk"
    assert it.last_used == "2026-01-15T18:00:00Z"
    assert it.dns == "1.1.1.1;9.9.9.9;"
    j = " ".join(it.notable)
    assert "PSK stored in the clear" in j
    assert "spoofed MAC address (DE:AD:BE:EF:00:11)" in j
    assert "public DNS server set (1.1.1.1)" in j


def test_nm_open_autoconnect(tmp_path):
    it = _items(tmp_path)[("nm-connection", "AirportFree")]
    assert any("autoconnect to an open" in n for n in it.notable)


def test_nm_static_and_proxy(tmp_path):
    it = _items(tmp_path)[("nm-connection", "Wired")]
    assert it.ipv4_method == "manual"
    assert it.addresses == "192.168.1.50/24,192.168.1.1"
    assert it.gateway == "192.168.1.1"
    assert "http://10.0.0.5/proxy.pac" in it.proxy
    assert any("proxy configured" in n for n in it.notable)


def test_nm_vpn(tmp_path):
    it = _items(tmp_path)[("nm-connection", "CorpVPN")]
    assert it.conn_type == "vpn"
    assert it.vpn_gateway == "vpn.corp.example:1194"
    assert it.secret_stored == "vpn"
    assert any("VPN credential stored" in n for n in it.notable)


def test_wpa_supplicant(tmp_path):
    its = _items(tmp_path)
    lab = its[("wpa-network", "LabNet")]
    assert lab.security == "WPA-PSK"
    assert lab.secret_stored == "psk"
    guest = its[("wpa-network", "OpenGuest")]
    assert guest.security == "NONE"
    assert guest.secret_stored == ""


def test_netplan_besteffort(tmp_path):
    its = _items(tmp_path)
    eth = its[("netplan", "eth0")]
    assert eth.ipv4_method == "dhcp"
    assert "8.8.8.8" in eth.dns and "1.1.1.1" in eth.dns
    wlan = its[("netplan", "wlan0")]
    assert wlan.conn_type == "wifi"
    assert wlan.secret_stored == "psk"


def test_networkd(tmp_path):
    it = _items(tmp_path)[("networkd", "eth1")]
    assert it.addresses == "10.10.0.2/24"
    assert it.gateway == "10.10.0.1"
    assert it.ipv4_method == "manual"


def test_hosts_and_resolv(tmp_path):
    its = _items(tmp_path)
    hostrows = [i for (k, _n), i in its.items() if k == "hosts-entry"]
    joined = " ".join(n for i in hostrows for n in i.notable)
    assert "overrides a security / update domain" in joined     # windowsupdate
    assert "blackholes a public domain" in joined               # 0.0.0.0
    assert "maps a public domain to 185.220.101.5" in joined    # github.com
    # localhost lines produced no entries
    assert not any("localhost" in i.name for i in hostrows)

    rv = its[("resolv", "resolv.conf")]
    assert "8.8.8.8" in rv.dns
    assert any("public DNS server set (8.8.8.8)" in n for n in rv.notable)


def test_cli_csv_json_filters(tmp_path):
    S.build_tree(tmp_path)
    csv_p = tmp_path / "n.csv"
    js_p = tmp_path / "n.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert isinstance(data, list) and data
    # the PSK value itself is never emitted
    blob = js_p.read_text()
    assert "SuperSecret123" not in blob
    assert "coffee123" not in blob
    assert "hunter2" not in blob

    main([str(tmp_path), "--kind", "nm-connection", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["kind"] == "nm-connection" for r in got)

    main([str(tmp_path), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_csv_injection_guard():
    from linux_networkmgr.tracelib import sanitize
    assert sanitize("=1+1") == "'=1+1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
