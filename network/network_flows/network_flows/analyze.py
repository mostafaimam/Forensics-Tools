"""Aggregate unidirectional flow records into conversations + summaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from network_flows import flags as _flags
from network_flows import records as _records


def _iso(ts):
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + "Z"


def _tcp_flag_str(bits: int) -> str:
    return "".join(c for b, c in ((0x01, "F"), (0x02, "S"), (0x04, "R"),
                                  (0x08, "P"), (0x10, "A"), (0x20, "U"))
                   if bits & b)


@dataclass
class Conv:
    proto: int
    client: str
    server: str
    server_port: int
    c2s_bytes: int = 0
    c2s_packets: int = 0
    s2c_bytes: int = 0
    s2c_packets: int = 0
    first: float | None = None
    last: float | None = None
    flows: int = 0
    tcp_flags: int = 0
    exporters: set = field(default_factory=set)
    sizes: list = field(default_factory=list)      # [(ts, bytes_this_flow)]
    src_as: int = 0
    dst_as: int = 0
    notable: list = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return self.c2s_bytes + self.s2c_bytes

    @property
    def total_packets(self) -> int:
        return self.c2s_packets + self.s2c_packets

    @property
    def duration(self) -> float:
        if self.first is None or self.last is None:
            return 0.0
        return max(0.0, self.last - self.first)

    def proto_name(self) -> str:
        return _records.Flow(proto=self.proto).proto_name

    def row(self) -> dict:
        return {
            "first_seen": _iso(self.first), "last_seen": _iso(self.last),
            "duration_s": round(self.duration, 1),
            "proto": self.proto_name(),
            "client": self.client, "server": self.server,
            "server_port": self.server_port,
            "flows": self.flows,
            "bytes": self.total_bytes, "packets": self.total_packets,
            "bytes_c2s": self.c2s_bytes, "bytes_s2c": self.s2c_bytes,
            "tcp_flags": _tcp_flag_str(self.tcp_flags),
            "src_as": self.src_as or "", "dst_as": self.dst_as or "",
            "exporters": ",".join(sorted(self.exporters)),
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    conversations: list = field(default_factory=list)
    flows: int = 0
    kinds: dict = field(default_factory=dict)
    talkers: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    protocols: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def _server_of(f: _records.Flow) -> tuple:
    a, b = (f.src, f.sport), (f.dst, f.dport)
    if f.proto in (6, 17) and f.sport and f.dport:
        return a if f.sport < f.dport else b
    return b


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    convs: dict[tuple, Conv] = {}
    for path in paths:
        try:
            for f in _records.read(path):
                res.flows += 1
                res.kinds[f.kind] = res.kinds.get(f.kind, 0) + 1
                if not f.src or not f.dst:
                    continue
                (sip, sport) = _server_of(f)
                cip = f.dst if (sip, sport) == (f.src, f.sport) else f.src
                key = (f.proto, cip, sip, sport)
                c = convs.get(key)
                if c is None:
                    c = convs[key] = Conv(proto=f.proto, client=cip,
                                          server=sip, server_port=sport)
                if f.src == cip:
                    c.c2s_bytes += f.bytes
                    c.c2s_packets += f.packets
                else:
                    c.s2c_bytes += f.bytes
                    c.s2c_packets += f.packets
                c.flows += 1
                c.tcp_flags |= f.tcp_flags
                c.exporters.add(f.exporter)
                c.src_as = c.src_as or f.src_as
                c.dst_as = c.dst_as or f.dst_as
                for t in (f.first, f.last):
                    if t is None:
                        continue
                    c.first = t if c.first is None else min(c.first, t)
                    c.last = t if c.last is None else max(c.last, t)
                if f.first is not None:
                    c.sizes.append((f.first, f.bytes))
                if progress and res.flows % 20000 == 0:
                    progress(res.flows)
        except (_records.FlowError, OSError) as e:
            res.errors.append(str(e))

    conv_list = list(convs.values())

    host_bytes: dict[str, int] = {}
    port_stat: dict[tuple, list] = {}
    fanout: dict[str, set] = {}
    for c in conv_list:
        host_bytes[c.client] = host_bytes.get(c.client, 0) + c.total_bytes
        host_bytes[c.server] = host_bytes.get(c.server, 0) + c.total_bytes
        st = port_stat.setdefault((c.proto_name(), c.server_port), [0, 0])
        st[0] += 1
        st[1] += c.total_bytes
        fanout.setdefault(c.client, set()).add(c.server)
        res.protocols[c.proto_name()] = (
            res.protocols.get(c.proto_name(), 0) + c.total_bytes)

    for c in conv_list:
        c.notable = _flags.flag(c, fanout.get(c.client, set()))

    res.conversations = sorted(
        conv_list, key=lambda c: (c.first is None, c.first or 0.0))
    res.talkers = sorted(host_bytes.items(), key=lambda kv: -kv[1])[:20]
    res.ports = sorted(
        [[proto, port, n, by] for (proto, port), (n, by) in port_stat.items()],
        key=lambda r: -r[3])[:20]
    return res
