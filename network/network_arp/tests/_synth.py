"""Hand-built ARP frames + pcap for the network_arp test-suite."""

from __future__ import annotations

import socket
import struct


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def arp_frame(op, sha, spa, tha, tpa, *, vlan=None):
    eth = _mac(tha if op == 2 else "ff:ff:ff:ff:ff:ff") + _mac(sha)
    if vlan:
        eth += struct.pack(">HH", 0x8100, vlan) + struct.pack(">H", 0x0806)
    else:
        eth += struct.pack(">H", 0x0806)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op)
    arp += _mac(sha) + socket.inet_aton(spa)
    arp += _mac(tha) + socket.inet_aton(tpa)
    return eth + arp


def ip_frame(src_mac, src_ip, dst_ip):
    eth = _mac("02:00:00:00:00:99") + _mac(src_mac) + struct.pack(">H", 0x0800)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    tcp = struct.pack(">HHIIBBHHH", 40000, 80, 1, 1, 0x50, 0x10, 0xFFFF, 0, 0)
    return eth + ip + tcp


def pcap(frames, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0x40000, linktype)
    t = 1_700_000_000.0
    for i, data in enumerate(frames):
        ts = t + i * 2
        sec = int(ts)
        frac = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, frac, len(data), len(data)) + data
    return out


DHCPD_LEASES = """\
lease 192.168.1.50 {
  starts 3 2026/11/14 09:00:00;
  ends 3 2026/11/14 21:00:00;
  binding state active;
  hardware ethernet 08:00:27:11:22:33;
  client-hostname "laptop-alice";
}
lease 192.168.1.51 {
  starts 3 2026/11/14 10:30:00;
  ends 3 2026/11/14 22:30:00;
  binding state active;
  hardware ethernet 00:0c:29:aa:bb:cc;
  client-hostname "desktop-bob";
}
"""

WIN_DHCP = """\
Microsoft DHCP Service Activity Log

ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,TransactionID,QResult,Probationtime,CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError
10,11/14/26,09:15:00,Assign,192.168.1.60,phone-carol.corp,A1B2C3D4E5F6,,,0,6,,,,,,,,,
11,11/14/26,12:00:00,Renew,192.168.1.60,phone-carol.corp,A1B2C3D4E5F6,,,0,6,,,,,,,,,
"""

ARP_TABLE = """\
? (192.168.1.1) at aa:bb:cc:00:00:01 [ether] on eth0
gateway (192.168.1.1) at aa:bb:cc:00:00:01 [ether] on eth0
? (192.168.1.50) at 08:00:27:11:22:33 [ether] on eth0
192.168.1.99 dev eth0 lladdr de:ad:be:ef:00:99 REACHABLE
"""

WIN_ARP_TABLE = """\
Interface: 192.168.1.5 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-00-00-01     dynamic
  192.168.1.77          02-11-22-33-44-55     dynamic
"""
