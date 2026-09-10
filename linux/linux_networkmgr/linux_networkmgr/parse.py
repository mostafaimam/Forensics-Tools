"""Parsers for the individual network-config formats."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Item:
    kind: str = ""            # nm-connection | wpa-network | networkd |
    name: str = ""            # netplan | hosts-entry | resolv
    source: str = ""
    conn_type: str = ""       # wifi | ethernet | vpn | ...
    uuid: str = ""
    autoconnect: str = ""
    last_used: str = ""       # ISO UTC
    ssid: str = ""
    bssid: str = ""
    security: str = ""        # key-mgmt
    secret_stored: str = ""   # "" | psk | 802-1x | vpn | wep
    mac: str = ""
    cloned_mac: str = ""
    ipv4_method: str = ""
    addresses: str = ""
    gateway: str = ""
    dns: str = ""
    routes: str = ""
    proxy: str = ""
    vpn_service: str = ""
    vpn_gateway: str = ""
    detail: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "kind": self.kind, "name": self.name, "source": self.source,
            "conn_type": self.conn_type, "uuid": self.uuid,
            "autoconnect": self.autoconnect, "last_used": self.last_used,
            "ssid": self.ssid, "bssid": self.bssid, "security": self.security,
            "secret_stored": self.secret_stored, "mac": self.mac,
            "cloned_mac": self.cloned_mac, "ipv4_method": self.ipv4_method,
            "addresses": self.addresses, "gateway": self.gateway,
            "dns": self.dns, "routes": self.routes, "proxy": self.proxy,
            "vpn_service": self.vpn_service, "vpn_gateway": self.vpn_gateway,
            "detail": self.detail, "notable": ";".join(self.notable),
        }


# --------------------------------------------------------------- keyfile INI
def _ini(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    sect = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            sect = line[1:-1]
            out.setdefault(sect, {})
            continue
        if "=" in line and sect:
            k, _, v = line.partition("=")
            out[sect][k.strip()] = v.strip()
    return out


def _iso(epoch) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError, TypeError):
        return ""


def parse_nmconnection(text: str, source: str) -> Item:
    d = _ini(text)
    conn = d.get("connection", {})
    it = Item(kind="nm-connection", source=source,
              name=conn.get("id", ""), uuid=conn.get("uuid", ""),
              conn_type=conn.get("type", ""),
              autoconnect=conn.get("autoconnect", "true"),
              last_used=_iso(conn.get("timestamp")))
    wifi = d.get("wifi", d.get("802-11-wireless", {}))
    if wifi:
        it.ssid = wifi.get("ssid", "")
        it.bssid = wifi.get("bssid", "") or wifi.get("seen-bssids", "")
        it.cloned_mac = wifi.get("cloned-mac-address", "")
        it.mac = wifi.get("mac-address", "")
    eth = d.get("ethernet", d.get("802-3-ethernet", {}))
    if eth:
        it.cloned_mac = it.cloned_mac or eth.get("cloned-mac-address", "")
        it.mac = it.mac or eth.get("mac-address", "")
    sec = d.get("wifi-security", d.get("802-11-wireless-security", {}))
    if sec:
        it.security = sec.get("key-mgmt", "")
        if sec.get("psk"):
            it.secret_stored = "psk"
        elif "wep-key0" in sec:
            it.secret_stored = "wep"
    x = d.get("802-1x", {})
    if x:
        it.security = it.security or "802.1x"
        it.detail = f"eap={x.get('eap', '')} identity={x.get('identity', '')}"
        if x.get("password") or x.get("private-key-password") or \
                x.get("phase2-private-key-password"):
            it.secret_stored = "802-1x"
    ip4 = d.get("ipv4", {})
    it.ipv4_method = ip4.get("method", "")
    addrs = [v for k, v in sorted(ip4.items()) if k.startswith("address")]
    it.addresses = ";".join(addrs)
    it.gateway = ip4.get("gateway", "") or (addrs[0].split(",")[1]
                                            if addrs and "," in addrs[0] else "")
    it.dns = ip4.get("dns", "")
    it.routes = ";".join(v for k, v in sorted(ip4.items())
                         if k.startswith("route"))
    px = d.get("proxy", {})
    if px and px.get("method", "none") != "none":
        it.proxy = f"{px.get('method', '')} {px.get('pac-url', '')}".strip()
    vpn = d.get("vpn", {})
    if vpn:
        it.conn_type = it.conn_type or "vpn"
        it.vpn_service = vpn.get("service-type", "")
        data = vpn.get("data", "")
        m = re.search(r"(?:gateway|remote|server)\s*=\s*([^\s,]+)", data)
        it.vpn_gateway = m.group(1) if m else ""
        if "password" in text.lower() and "password-flags=1" not in text \
                and "password-flags = 1" not in text:
            it.secret_stored = it.secret_stored or "vpn"
    return it


# ----------------------------------------------------------- wpa_supplicant
_NET_BLOCK = re.compile(r"network\s*=\s*\{(.*?)\}", re.S)
_KV = re.compile(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|\S+)')


def parse_wpa_supplicant(text: str, source: str) -> list[Item]:
    out = []
    for m in _NET_BLOCK.finditer(text):
        body = m.group(1)
        kv = {k: v.strip('"') for k, v in _KV.findall(body)}
        it = Item(kind="wpa-network", source=source, conn_type="wifi",
                  name=kv.get("ssid", "") or kv.get("id_str", ""),
                  ssid=kv.get("ssid", ""), bssid=kv.get("bssid", ""),
                  security=kv.get("key_mgmt", "WPA-PSK"))
        if kv.get("psk"):
            it.secret_stored = "psk"
        if kv.get("password") or kv.get("private_key_passwd"):
            it.secret_stored = "802-1x"
        if kv.get("identity"):
            it.detail = f"identity={kv['identity']}"
        out.append(it)
    return out


# ------------------------------------------------------------- systemd-networkd
def parse_networkd(text: str, source: str) -> Item:
    d = _ini(text)
    net = d.get("Network", {})
    match = d.get("Match", {})
    it = Item(kind="networkd", source=source,
              name=match.get("Name", "") or match.get("MACAddress", "")
              or "network")
    it.ipv4_method = "dhcp" if net.get("DHCP", "no").lower() in (
        "yes", "ipv4", "true") else "manual"
    it.addresses = net.get("Address", "")
    it.gateway = net.get("Gateway", "")
    it.dns = net.get("DNS", "")
    return it


# --------------------------------------------------------------------- netplan
def parse_netplan(text: str, source: str) -> list[Item]:
    """Best-effort indent-driven read - NOT a full YAML parser.

    Recognises ``network: {ethernets|wifis|...: <dev>: ...}`` and pulls
    ``dhcp4``, ``addresses``, ``gateway4``, ``nameservers: addresses``,
    ``access-points`` and any ``password``.
    """
    out: list[Item] = []
    lines = [ln for ln in text.splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    cur: Item | None = None
    group = ""                 # ethernets | wifis | ...
    group_indent = -1
    dev_indent = -1
    in_ns = False
    for ln in lines:
        indent = len(ln) - len(ln.lstrip())
        s = ln.strip()
        key, sep, val = s.partition(":")
        key = key.strip()
        val = val.strip().strip("'\"")
        low = key.lower()

        if low in ("ethernets", "wifis", "bridges", "vlans", "bonds",
                   "tunnels", "modems", "vrfs"):
            if cur:
                out.append(cur)
            group, group_indent, cur, dev_indent = low, indent, None, -1
            continue
        if group and indent > group_indent and dev_indent in (-1, indent) \
                and sep and not val and low not in ("nameservers", "match",
                                                    "access-points", "auth"):
            if cur:
                out.append(cur)
            dev_indent = indent
            cur = Item(kind="netplan", source=source, name=key,
                       conn_type="wifi" if group == "wifis" else "ethernet")
            in_ns = False
            continue
        if cur is None:
            continue
        if low == "nameservers":
            in_ns = True
            continue
        if in_ns and low == "addresses":
            cur.dns = val.strip("[]").replace(",", " ").strip()
            continue
        if low in ("dhcp4", "dhcp6") and val.lower() in ("true", "yes"):
            cur.ipv4_method = "dhcp"
        elif low == "addresses" and val:
            cur.addresses = (cur.addresses + " "
                             + val.strip("[]").replace(",", " ")).strip()
        elif s.startswith("- ") and not sep:
            cur.addresses = (cur.addresses + " " + s[2:].strip()).strip()
        elif low in ("gateway4", "gateway6"):
            cur.gateway = val
        elif low == "access-points":
            cur.conn_type = "wifi"
        elif low == "password" and val:
            cur.secret_stored = "psk"
        elif group == "wifis" and sep and not val and cur.ssid == "" \
                and indent > dev_indent + 2:
            cur.ssid = key.strip('"')
    if cur:
        out.append(cur)
    return out


# ------------------------------------------------------------------ /etc/hosts
_PUBLIC_DOMAIN = re.compile(
    r"\b([a-z0-9-]+\.)+(com|net|org|io|dev|gov|edu|co|ru|cn|info|update|"
    r"microsoft\.com|windows\.com|apple\.com|ubuntu\.com|debian\.org|"
    r"clamav\.net|virustotal\.com)\b", re.I)


def parse_hosts(text: str, source: str) -> list[Item]:
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        std = ip in ("127.0.0.1", "::1", "127.0.1.1", "fe00::0", "ff00::0",
                     "ff02::1", "ff02::2", "255.255.255.255")
        std_names = {"localhost", "localhost.localdomain", "localhost4",
                     "localhost6", "ip6-localhost", "ip6-loopback",
                     "ip6-allnodes", "ip6-allrouters", "ip6-mcastprefix",
                     "broadcasthost"}
        if std and all(nm in std_names or nm == _hostname_guess(text)
                       for nm in names):
            continue
        it = Item(kind="hosts-entry", source=source, name=" ".join(names),
                  addresses=ip, detail=line)
        out.append(it)
    return out


def _hostname_guess(text: str) -> str:
    m = re.search(r"127\.0\.1\.1\s+(\S+)", text)
    return m.group(1) if m else ""


# ------------------------------------------------------------- /etc/resolv.conf
def parse_resolv(text: str, source: str) -> Item:
    ns = re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)
    search = re.findall(r"^\s*search\s+(.+)$", text, re.M)
    it = Item(kind="resolv", source=source, name="resolv.conf",
              dns=";".join(ns), detail=("search " + " ".join(search))
              if search else "")
    return it
