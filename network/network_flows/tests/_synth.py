"""Hand-built NetFlow v5 / v9, IPFIX and sFlow exports for the test-suite."""

from __future__ import annotations

import socket
import struct

BASE = 1_700_000_000       # export unix time
UPTIME_MS = 3_600_000      # device up 1 h


def _ip(s):
    return socket.inet_aton(s)


# --------------------------------------------------------------------------
# NetFlow v5
# --------------------------------------------------------------------------

def nf5(records, *, base=BASE, uptime=UPTIME_MS):
    """records: list of dicts {src,dst,sport,dport,proto,pkts,octets,
    first_ago,last_ago,tcp_flags}"""
    hdr = struct.pack(">HHIIIIBBH", 5, len(records), uptime, base, 0, 0,
                      0, 0, 0)
    body = b""
    for r in records:
        first = uptime - int(r.get("first_ago", 10) * 1000)
        last = uptime - int(r.get("last_ago", 0) * 1000)
        body += struct.pack(
            ">IIIHHIIIIHHBBBBHHBBH",
            struct.unpack(">I", _ip(r["src"]))[0],
            struct.unpack(">I", _ip(r["dst"]))[0], 0,
            0, 0, r.get("pkts", 1), r.get("octets", 100), first, last,
            r.get("sport", 12345), r.get("dport", 80), 0,
            r.get("tcp_flags", 0), r.get("proto", 6), 0,
            r.get("src_as", 0), r.get("dst_as", 0), 0, 0, 0)
    return hdr + body


# --------------------------------------------------------------------------
# NetFlow v9
# --------------------------------------------------------------------------

_V9_TEMPLATE_ID = 256
# (type, length) - IPV4_SRC, IPV4_DST, L4_SRC_PORT, L4_DST_PORT, PROTOCOL,
#   IN_PKTS, IN_BYTES, TCP_FLAGS, FIRST_SWITCHED, LAST_SWITCHED
_V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4),
              (6, 1), (22, 4), (21, 4)]


def nf9(records, *, base=BASE, uptime=UPTIME_MS, source_id=1,
        with_template=True):
    tmpl = b""
    if with_template:
        t = struct.pack(">HH", _V9_TEMPLATE_ID, len(_V9_FIELDS))
        for ty, ln in _V9_FIELDS:
            t += struct.pack(">HH", ty, ln)
        tmpl = struct.pack(">HH", 0, 4 + len(t)) + t

    data = b""
    for r in records:
        first = uptime - int(r.get("first_ago", 10) * 1000)
        last = uptime - int(r.get("last_ago", 0) * 1000)
        data += (_ip(r["src"]) + _ip(r["dst"])
                 + struct.pack(">HHBIIBII", r.get("sport", 12345),
                               r.get("dport", 80), r.get("proto", 6),
                               r.get("pkts", 1), r.get("octets", 100),
                               r.get("tcp_flags", 0), first, last))
    dfs = struct.pack(">HH", _V9_TEMPLATE_ID, 4 + len(data)) + data

    count = (len(_V9_FIELDS) if with_template else 0) + 0 + len(records)
    hdr = struct.pack(">HHIIII", 9, count, uptime, base, 0, source_id)
    return hdr + tmpl + dfs


# --------------------------------------------------------------------------
# IPFIX
# --------------------------------------------------------------------------

_IPFIX_TEMPLATE_ID = 300
# sourceIPv4Address, destinationIPv4Address, sourceTransportPort,
# destinationTransportPort, protocolIdentifier, packetDeltaCount,
# octetDeltaCount, tcpControlBits, flowStartMilliseconds, flowEndMilliseconds
_IPFIX_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4),
                 (6, 1), (152, 8), (153, 8)]


def ipfix(records, *, export_time=BASE, domain=1, with_template=True):
    tmpl = b""
    if with_template:
        t = struct.pack(">HH", _IPFIX_TEMPLATE_ID, len(_IPFIX_FIELDS))
        for ie, ln in _IPFIX_FIELDS:
            t += struct.pack(">HH", ie, ln)
        tmpl = struct.pack(">HH", 2, 4 + len(t)) + t

    data = b""
    for r in records:
        fs = int(r.get("first_ms", export_time * 1000))
        fe = int(r.get("last_ms", export_time * 1000 + 5000))
        data += (_ip(r["src"]) + _ip(r["dst"])
                 + struct.pack(">HHBIIB", r.get("sport", 12345),
                               r.get("dport", 443), r.get("proto", 6),
                               r.get("pkts", 1), r.get("octets", 100),
                               r.get("tcp_flags", 0))
                 + struct.pack(">QQ", fs, fe))
    ds = struct.pack(">HH", _IPFIX_TEMPLATE_ID, 4 + len(data)) + data

    body = tmpl + ds
    hdr = struct.pack(">HHIII", 10, 16 + len(body), export_time, 0, domain)
    return hdr + body


# --------------------------------------------------------------------------
# sFlow v5 - flow sample with a raw Ethernet/IPv4/TCP header
# --------------------------------------------------------------------------

def _eth_ip_tcp(src, dst, sport, dport, frame_len):
    eth = (b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01"
           + struct.pack(">H", 0x0800))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
                     _ip(src), _ip(dst))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x10,
                      0xFFFF, 0, 0)
    return eth + ip + tcp


def sflow(records, *, agent="10.0.0.1", rate=1024):
    hdr = struct.pack(">II", 5, 1) + _ip(agent) + struct.pack(">III", 0, 1,
                                                              UPTIME_MS)
    hdr += struct.pack(">I", len(records))
    out = hdr
    for r in records:
        header = _eth_ip_tcp(r["src"], r["dst"], r.get("sport", 40000),
                             r.get("dport", 443), r.get("frame_len", 1500))
        # raw packet header flow record (data format 1)
        rec = struct.pack(">IIII", 1, r.get("frame_len", 1500), 0,
                          len(header)) + header
        pad = (-len(rec)) % 4
        rec += b"\x00" * pad
        flow_rec = struct.pack(">II", 1, len(rec) - pad) + rec
        # flow sample (sample type format 1)
        sample_body = struct.pack(">IIIIIIII", 1, 0, rate, 0, 0,
                                  0, 0, 1) + flow_rec
        out += struct.pack(">II", 1, len(sample_body)) + sample_body
    return out
