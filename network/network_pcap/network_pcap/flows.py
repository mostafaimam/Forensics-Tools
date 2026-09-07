"""Reassemble decoded packets into bidirectional flows + app-layer records."""

from __future__ import annotations

from dataclasses import dataclass, field

from network_pcap.appproto import parse_dns, parse_http
from network_pcap.layers import Packet


@dataclass
class Flow:
    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    first_ts: float = 0.0
    last_ts: float = 0.0
    a2b_pkts: int = 0
    b2a_pkts: int = 0
    a2b_bytes: int = 0
    b2a_bytes: int = 0
    tcp_flags: set = field(default_factory=set)
    service: str = ""            # guessed L7 service
    server_ip: str = ""          # the listening side
    notable: list = field(default_factory=list)

    @property
    def packets(self) -> int:
        return self.a2b_pkts + self.b2a_pkts

    @property
    def bytes(self) -> int:
        return self.a2b_bytes + self.b2a_bytes

    @property
    def duration(self) -> float:
        return round(self.last_ts - self.first_ts, 3)

    @property
    def client_ip(self) -> str:
        return self.b_ip if self.server_ip == self.a_ip else self.a_ip

    @property
    def egress_bytes(self) -> int:
        """Bytes sent by the client."""
        if self.server_ip == self.a_ip:
            return self.b2a_bytes
        return self.a2b_bytes


@dataclass
class DnsRec:
    ts: float
    client: str
    server: str
    query: str
    qtype: str
    response: bool
    rcode: int
    answers: list
    notable: list = field(default_factory=list)


@dataclass
class HttpRec:
    ts: float
    client: str
    server: str
    server_port: int
    method: str = ""
    host: str = ""
    target: str = ""
    status: int = 0
    user_agent: str = ""
    content_type: str = ""
    referer: str = ""
    authorization: str = ""
    server_hdr: str = ""
    body_preview: str = ""
    has_password_field: bool = False
    notable: list = field(default_factory=list)

    @property
    def url(self) -> str:
        if self.host and self.target.startswith("/"):
            scheme = "https" if self.server_port == 443 else "http"
            return f"{scheme}://{self.host}{self.target}"
        return self.target


_WELL_KNOWN = {
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 88: "kerberos",
    123: "ntp", 135: "msrpc", 137: "netbios", 138: "netbios", 139: "smb",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    21: "ftp", 20: "ftp-data", 23: "telnet", 25: "smtp", 110: "pop3",
    22: "ssh",
}
_PLAINTEXT = {"http", "ftp", "telnet", "smtp", "pop3", "imap", "snmp",
              "syslog", "redis", "http-alt"}


def _service(port_a: int, port_b: int) -> tuple[str, int]:
    lo = min(port_a, port_b)
    hi = max(port_a, port_b)
    for p in (lo, hi):
        if p in _WELL_KNOWN:
            return _WELL_KNOWN[p], p
    return "", 0


class Reassembler:
    def __init__(self):
        self.flows: dict[tuple, Flow] = {}
        self.dns: list[DnsRec] = []
        self.http: list[HttpRec] = []
        self._http_seen: set = set()
        self._pending_req: dict[tuple, HttpRec] = {}

    def add(self, p: Packet) -> None:
        if not p.src or p.proto not in ("TCP", "UDP"):
            if p.proto in ("ICMP", "ICMPv6", "ARP"):
                self._other(p)
            return
        a = (p.src, p.sport)
        b = (p.dst, p.dport)
        key = (p.proto, min(a, b), max(a, b))
        f = self.flows.get(key)
        if f is None:
            (a_ip, a_port), (b_ip, b_port) = min(a, b), max(a, b)
            svc, svc_port = _service(a_port, b_port)
            f = Flow(proto=p.proto, a_ip=a_ip, a_port=a_port,
                     b_ip=b_ip, b_port=b_port, first_ts=p.ts, service=svc)
            # server = the endpoint on the well-known port, else the dst of
            # the first packet
            if svc_port == a_port:
                f.server_ip = a_ip
            elif svc_port == b_port:
                f.server_ip = b_ip
            else:
                f.server_ip = p.dst
            self.flows[key] = f
        f.last_ts = p.ts
        forward = (p.src, p.sport) == (f.a_ip, f.a_port)
        if forward:
            f.a2b_pkts += 1
            f.a2b_bytes += p.length
        else:
            f.b2a_pkts += 1
            f.b2a_bytes += p.length
        if p.tcp_flags:
            f.tcp_flags.update(c for c in p.tcp_flags if c != ".")

        if p.payload:
            self._app(p, f)

    def _app(self, p: Packet, f: Flow) -> None:
        if p.dport == 53 or p.sport == 53:
            d = parse_dns(p.payload)
            if d and d["queries"]:
                client = p.src if p.dport == 53 else p.dst
                server = p.dst if p.dport == 53 else p.src
                q, qt = d["queries"][0]
                self.dns.append(DnsRec(
                    ts=p.ts, client=client, server=server, query=q, qtype=qt,
                    response=d["response"], rcode=d["rcode"],
                    answers=d["answers"]))
                if not f.service:
                    f.service = "dns"
            return
        if p.proto == "TCP" and (p.payload[:4] in
                                 (b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP")
                                 or p.payload.startswith((b"DELETE", b"OPTIONS",
                                                          b"PATCH", b"CONNECT")
                                                         )):
            h = parse_http(p.payload)
            if not h:
                return
            server_ip = f.server_ip
            server_port = f.b_port if server_ip == f.b_ip else f.a_port
            client_ip = f.client_ip
            convo = (client_ip, server_ip, server_port)
            if h.get("kind") == "response":
                req = self._pending_req.pop(convo, None)
                if req is not None and not req.status:
                    req.status = h.get("status", 0)
                    if h.get("content_type") and not req.content_type:
                        req.content_type = h["content_type"]
                    if h.get("server"):
                        req.server_hdr = h["server"]
                    return
            sig = (client_ip, server_ip, server_port, h.get("target"),
                   h.get("status"), round(p.ts, 1))
            if sig in self._http_seen:
                return
            self._http_seen.add(sig)
            rec = HttpRec(
                ts=p.ts, client=client_ip, server=server_ip,
                server_port=server_port, method=h.get("method", ""),
                host=h.get("host", ""), target=h.get("target", ""),
                status=h.get("status", 0), user_agent=h.get("user_agent", ""),
                content_type=h.get("content_type", ""),
                referer=h.get("referer", ""),
                authorization=h.get("authorization", ""),
                server_hdr=h.get("server", ""),
                body_preview=h.get("body_preview", ""),
                has_password_field=h.get("body_has_password_field", False))
            self.http.append(rec)
            if rec.method:
                self._pending_req[convo] = rec
            if not f.service or f.service == "http-alt":
                f.service = "http"

    def _other(self, p: Packet) -> None:
        key = (p.proto, p.src, p.dst)
        f = self.flows.get(key)
        if f is None:
            f = Flow(proto=p.proto, a_ip=p.src, a_port=0, b_ip=p.dst,
                     b_port=0, first_ts=p.ts, server_ip=p.dst)
            self.flows[key] = f
        f.last_ts = p.ts
        f.a2b_pkts += 1
        f.a2b_bytes += p.length

    def result(self):
        flows = sorted(self.flows.values(), key=lambda x: x.first_ts)
        return flows, self.dns, self.http
