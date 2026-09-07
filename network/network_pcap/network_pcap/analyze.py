"""Read a capture, decode, reassemble, flag."""

from __future__ import annotations

from dataclasses import dataclass, field

from network_pcap import flags as _flags
from network_pcap import pcap as _pcap
from network_pcap.flows import Reassembler
from network_pcap.layers import decode


@dataclass
class Capture:
    flows: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    http: list = field(default_factory=list)
    packets: int = 0
    decoded: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    files: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def analyze(paths, *, progress=None) -> Capture:
    cap = Capture()
    r = Reassembler()
    for path in paths:
        try:
            n = 0
            for ts, lt, data in _pcap.read(path):
                cap.packets += 1
                n += 1
                if ts:
                    cap.first_ts = ts if not cap.first_ts else min(
                        cap.first_ts, ts)
                    cap.last_ts = max(cap.last_ts, ts)
                pkt = decode(ts, lt, data)
                if pkt and pkt.src:
                    cap.decoded += 1
                    r.add(pkt)
                if progress and cap.packets % 5000 == 0:
                    progress(cap.packets)
            cap.files.append(f"{path} ({n} packets)")
        except _pcap.PcapError as e:
            cap.errors.append(f"{path}: {e}")
        except OSError as e:
            cap.errors.append(f"{path}: {e}")

    flows, dns, http = r.result()
    cap.flows, cap.dns, cap.http = flows, dns, http

    dns_names = set()
    for d in dns:
        d.notable = _flags.flag_dns(d)
        for atype, aval in d.answers:
            if atype in ("A", "AAAA") and aval:
                dns_names.add(aval)
    for h in http:
        h.notable = _flags.flag_http(h)
    for f in flows:
        f.notable = _flags.flag_flow(f, dns_names=dns_names)

    _port_scan_hint(cap)
    return cap


def _port_scan_hint(cap: Capture) -> None:
    by_src: dict[str, set] = {}
    for f in cap.flows:
        if f.proto != "TCP":
            continue
        client = f.client_ip
        by_src.setdefault(client, set()).add((f.server_ip, f.b_port
                                              if f.server_ip == f.b_ip
                                              else f.a_port))
    for src, targets in by_src.items():
        dsts = {t[0] for t in targets}
        ports = {t[1] for t in targets}
        if len(ports) >= 20 and len(dsts) <= 3:
            for f in cap.flows:
                if f.client_ip == src and f.proto == "TCP":
                    f.notable.append("part of a port scan")
        elif len(dsts) >= 25 and len(ports) <= 3:
            for f in cap.flows:
                if f.client_ip == src and f.proto == "TCP":
                    f.notable.append("part of a host sweep")
