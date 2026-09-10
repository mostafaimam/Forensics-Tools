"""Synthetic network-config tree for the linux_networkmgr test-suite."""

from __future__ import annotations

from pathlib import Path


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


NM_WIFI_HOME = """\
[connection]
id=HomeWiFi
uuid=11111111-1111-1111-1111-111111111111
type=wifi
autoconnect=true
timestamp=1768500000

[wifi]
ssid=HomeWiFi
mode=infrastructure
cloned-mac-address=DE:AD:BE:EF:00:11

[wifi-security]
key-mgmt=wpa-psk
psk=SuperSecret123

[ipv4]
method=auto
dns=1.1.1.1;9.9.9.9;

[ipv6]
method=auto
"""

NM_WIFI_OPEN = """\
[connection]
id=AirportFree
uuid=22222222-2222-2222-2222-222222222222
type=wifi
autoconnect=true
timestamp=1768400000

[wifi]
ssid=AirportFree
mode=infrastructure

[ipv4]
method=auto
"""

NM_ETH_STATIC = """\
[connection]
id=Wired
uuid=33333333-3333-3333-3333-333333333333
type=ethernet
autoconnect=true

[ethernet]

[ipv4]
method=manual
address1=192.168.1.50/24,192.168.1.1
dns=192.168.1.1;

[proxy]
method=auto
pac-url=http://10.0.0.5/proxy.pac
"""

NM_VPN = """\
[connection]
id=CorpVPN
uuid=44444444-4444-4444-4444-444444444444
type=vpn
autoconnect=false

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
data=remote=vpn.corp.example:1194, connection-type=password
password=hunter2

[ipv4]
method=auto
"""

WPA_CONF = """\
ctrl_interface=/run/wpa_supplicant
update_config=1

network={
    ssid="LabNet"
    key_mgmt=WPA-PSK
    psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
}

network={
    ssid="OpenGuest"
    key_mgmt=NONE
}
"""

NETPLAN = """\
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
  wifis:
    wlan0:
      access-points:
        "CafeWiFi":
          password: "coffee123"
      dhcp4: true
"""

NETWORKD = """\
[Match]
Name=eth1

[Network]
DHCP=no
Address=10.10.0.2/24
Gateway=10.10.0.1
DNS=10.10.0.1
"""

HOSTS = """\
127.0.0.1\tlocalhost
127.0.1.1\tmyhost
::1\tlocalhost ip6-localhost ip6-loopback

10.0.0.9\tinternal.corp.example
203.0.113.10\twindowsupdate.microsoft.com
0.0.0.0\ttelemetry.example.com
185.220.101.5\tgithub.com
"""

RESOLV = """\
# generated
nameserver 192.168.1.1
nameserver 8.8.8.8
search corp.example
"""


def build_tree(root: Path) -> Path:
    base = "etc/NetworkManager/system-connections"
    _w(root, f"{base}/HomeWiFi.nmconnection", NM_WIFI_HOME)
    _w(root, f"{base}/AirportFree.nmconnection", NM_WIFI_OPEN)
    _w(root, f"{base}/Wired.nmconnection", NM_ETH_STATIC)
    _w(root, f"{base}/CorpVPN.nmconnection", NM_VPN)
    _w(root, "etc/wpa_supplicant/wpa_supplicant.conf", WPA_CONF)
    _w(root, "etc/netplan/01-netcfg.yaml", NETPLAN)
    _w(root, "etc/systemd/network/20-wired.network", NETWORKD)
    _w(root, "etc/hosts", HOSTS)
    _w(root, "etc/resolv.conf", RESOLV)
    return root
