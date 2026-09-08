"""Parse NetFlow v5 / v9, IPFIX and sFlow into a normalised flow record."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from network_flows.layers import decode as _decode


class FlowError(Exception):
    pass


@dataclass
class Flow:
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    proto: int = 0
    packets: int = 0
    bytes: int = 0
    first: float | None = None       # epoch seconds
    last: float | None = None
    tcp_flags: int = 0
    src_as: int = 0
    dst_as: int = 0
    in_if: int = 0
    out_if: int = 0
    exporter: str = ""
    kind: str = ""                   # netflow5 | netflow9 | ipfix | sflow
    sampling: int = 1

    @property
    def proto_name(self) -> str:
        return {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
                58: "ICMPv6", 132: "SCTP"}.get(self.proto, str(self.proto))


# --------------------------------------------------------------------------
# NetFlow v5
# --------------------------------------------------------------------------

def _nf5(data: bytes, exporter: str):
    ver, count = struct.unpack_from(">HH", data, 0)
    (sys_uptime, unix_secs, unix_nsecs, seq) = struct.unpack_from(
        ">IIII", data, 4)
    sampling = struct.unpack_from(">H", data, 22)[0] & 0x3FFF or 1
    base = unix_secs + unix_nsecs / 1e9
    off = 24
    for _ in range(count):
        if off + 48 > len(data):
            break
        (sa, da, nh) = struct.unpack_from(">III", data, off)
        (i_if, o_if, dpkts, doct, first, last) = struct.unpack_from(
            ">HHIIII", data, off + 12)
        (sp, dp) = struct.unpack_from(">HH", data, off + 32)
        (tcpf, prot, tos) = struct.unpack_from(">BBB", data, off + 37)
        (s_as, d_as) = struct.unpack_from(">HH", data, off + 40)
        off += 48
        yield Flow(
            src=socket.inet_ntoa(struct.pack(">I", sa)),
            dst=socket.inet_ntoa(struct.pack(">I", da)),
            sport=sp, dport=dp, proto=prot, packets=dpkts, bytes=doct,
            first=base - (sys_uptime - first) / 1000.0,
            last=base - (sys_uptime - last) / 1000.0,
            tcp_flags=tcpf, src_as=s_as, dst_as=d_as, in_if=i_if, out_if=o_if,
            exporter=exporter, kind="netflow5", sampling=sampling)


# --------------------------------------------------------------------------
# NetFlow v9 / IPFIX  (shared field semantics)
# --------------------------------------------------------------------------

# IE number -> (attribute, interpretation)
_IE = {
    1: ("bytes", "uint"), 2: ("packets", "uint"), 4: ("proto", "uint"),
    5: ("tos", "uint"), 6: ("tcp_flags", "uint"), 7: ("sport", "uint"),
    8: ("src", "ipv4"), 10: ("in_if", "uint"), 11: ("dport", "uint"),
    12: ("dst", "ipv4"), 14: ("out_if", "uint"), 16: ("src_as", "uint"),
    17: ("dst_as", "uint"), 21: ("last_up", "uint"), 22: ("first_up", "uint"),
    27: ("src", "ipv6"), 28: ("dst", "ipv6"), 32: ("icmp_type", "uint"),
    60: ("ip_version", "uint"),
    85: ("bytes", "uint"), 86: ("packets", "uint"),
    150: ("first", "sec"), 151: ("last", "sec"),
    152: ("first", "msec"), 153: ("last", "msec"),
    156: ("first", "nsec"), 157: ("last", "nsec"),
    184: ("first", "sec"), 185: ("last", "sec"),
}


def _val(kind: str, raw: bytes):
    if kind == "uint":
        return int.from_bytes(raw, "big")
    if kind == "ipv4":
        return socket.inet_ntop(socket.AF_INET, raw) if len(raw) == 4 else ""
    if kind == "ipv6":
        return socket.inet_ntop(socket.AF_INET6, raw) if len(raw) == 16 else ""
    if kind in ("sec",):
        return int.from_bytes(raw, "big")
    if kind == "msec":
        return int.from_bytes(raw, "big") / 1000.0
    if kind == "nsec":
        return int.from_bytes(raw, "big") / 1e9
    return int.from_bytes(raw, "big")


class _TemplateStore:
    def __init__(self):
        self.t: dict[tuple, list] = {}          # (domain, tid) -> [(ie,len)]

    def put(self, domain, tid, fields):
        self.t[(domain, tid)] = fields

    def get(self, domain, tid):
        return self.t.get((domain, tid))


def _apply_template(fields, data, off, base_time, sys_uptime, exporter, kind):
    rec = Flow(exporter=exporter, kind=kind)
    first_up = last_up = None
    for ie, ln in fields:
        raw = data[off:off + ln]
        off += ln
        spec = _IE.get(ie)
        if not spec:
            continue
        attr, interp = spec
        v = _val(interp, raw)
        if attr == "first" and interp in ("sec", "msec", "nsec"):
            rec.first = float(v)
        elif attr == "last" and interp in ("sec", "msec", "nsec"):
            rec.last = float(v)
        elif attr == "first_up":
            first_up = v
        elif attr == "last_up":
            last_up = v
        elif attr in ("src", "dst"):
            if v:
                setattr(rec, attr, v)
        elif attr in ("bytes", "packets", "sport", "dport", "proto",
                      "tcp_flags", "src_as", "dst_as", "in_if", "out_if"):
            setattr(rec, attr, int(v))
    if rec.first is None and first_up is not None and base_time:
        rec.first = base_time - (sys_uptime - first_up) / 1000.0
    if rec.last is None and last_up is not None and base_time:
        rec.last = base_time - (sys_uptime - last_up) / 1000.0
    return rec, off


def _nf9(data: bytes, exporter: str, store: _TemplateStore):
    ver, count = struct.unpack_from(">HH", data, 0)
    sys_uptime, unix_secs, seq, source_id = struct.unpack_from(">IIII", data, 4)
    base = float(unix_secs)
    off = 20
    n = len(data)
    while off + 4 <= n:
        fs_id, fs_len = struct.unpack_from(">HH", data, off)
        if fs_len < 4 or off + fs_len > n:
            break
        body_end = off + fs_len
        p = off + 4
        if fs_id == 0:                                     # template flowset
            while p + 4 <= body_end:
                tid, fc = struct.unpack_from(">HH", data, p)
                p += 4
                fields = []
                for _ in range(fc):
                    if p + 4 > body_end:
                        break
                    t, ln = struct.unpack_from(">HH", data, p)
                    p += 4
                    fields.append((t, ln))
                if fields:
                    store.put(source_id, tid, fields)
        elif fs_id == 1:                                   # options template
            pass
        elif fs_id >= 256:                                 # data flowset
            fields = store.get(source_id, fs_id)
            if fields:
                rlen = sum(ln for _, ln in fields)
                while p + rlen <= body_end:
                    rec, p = _apply_template(fields, data, p, base,
                                             sys_uptime, exporter, "netflow9")
                    yield rec
        off = body_end


def _ipfix(data: bytes, exporter: str, store: _TemplateStore):
    ver, msg_len, export_time, seq, domain = struct.unpack_from(">HIIII", data, 0)
    base = float(export_time)
    off = 16
    n = min(len(data), msg_len) if msg_len else len(data)
    while off + 4 <= n:
        set_id, set_len = struct.unpack_from(">HH", data, off)
        if set_len < 4 or off + set_len > n:
            break
        body_end = off + set_len
        p = off + 4
        if set_id == 2:                                    # template set
            while p + 4 <= body_end:
                tid, fc = struct.unpack_from(">HH", data, p)
                p += 4
                fields = []
                for _ in range(fc):
                    if p + 4 > body_end:
                        break
                    ie, ln = struct.unpack_from(">HH", data, p)
                    p += 4
                    if ie & 0x8000:                        # enterprise field
                        ie &= 0x7FFF
                        p += 4
                    fields.append((ie, ln))
                if fields:
                    store.put(domain, tid, fields)
        elif set_id == 3:                                  # options template
            pass
        elif set_id >= 256:
            fields = store.get(domain, set_id)
            if fields and all(ln != 0xFFFF for _, ln in fields):
                rlen = sum(ln for _, ln in fields)
                while p + rlen <= body_end:
                    rec, p = _apply_template(fields, data, p, base, 0,
                                             exporter, "ipfix")
                    yield rec
        off = body_end


# --------------------------------------------------------------------------
# sFlow v5 (flow samples with a raw packet header)
# --------------------------------------------------------------------------

def _sflow(data: bytes, exporter: str):
    ver = struct.unpack_from(">I", data, 0)[0]
    if ver != 5:
        return
    addr_type = struct.unpack_from(">I", data, 4)[0]
    p = 8 + (4 if addr_type == 1 else 16 if addr_type == 2 else 0)
    p += 4                                                 # sub agent id
    p += 4                                                 # sequence
    p += 4                                                 # uptime
    n_samples = struct.unpack_from(">I", data, p)[0]
    p += 4
    for _ in range(n_samples):
        if p + 8 > len(data):
            break
        s_type, s_len = struct.unpack_from(">II", data, p)
        body = data[p + 8:p + 8 + s_len]
        p += 8 + s_len
        fmt = s_type & 0xFFF
        if fmt not in (1, 3):                              # flow sample
            continue
        yield from _sflow_flow_sample(body, exporter, expanded=(fmt == 3))


def _sflow_flow_sample(b: bytes, exporter: str, *, expanded: bool):
    try:
        if expanded:
            (seq, ds_class, ds_index, rate, pool, drops, in_fmt, in_val,
             out_fmt, out_val, nrec) = struct.unpack_from(">IIIIIIIIIII", b, 0)
            q = 44
            in_if, out_if = in_val, out_val
        else:
            (seq, source_id, rate, pool, drops, in_if, out_if,
             nrec) = struct.unpack_from(">IIIIIIII", b, 0)
            q = 32
    except struct.error:
        return
    for _ in range(nrec):
        if q + 8 > len(b):
            break
        d_fmt, d_len = struct.unpack_from(">II", b, q)
        rec = b[q + 8:q + 8 + d_len]
        q += 8 + d_len + ((-d_len) % 4)
        if (d_fmt & 0xFFF) != 1:                           # raw packet header
            continue
        try:
            hp, frame_len, stripped, hdr_len = struct.unpack_from(">IIII",
                                                                  rec, 0)
        except struct.error:
            continue
        header = rec[16:16 + hdr_len]
        lt = {1: 1}.get(hp, 1)                             # 1 = Ethernet
        pkt = _decode(0.0, lt, header)
        if not pkt or not pkt.src:
            continue
        yield Flow(
            src=pkt.src, dst=pkt.dst, sport=pkt.sport, dport=pkt.dport,
            proto={"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPv6": 58}.get(
                pkt.proto, 0),
            packets=1 * (rate or 1), bytes=frame_len * (rate or 1),
            tcp_flags=0, in_if=in_if, out_if=out_if,
            exporter=exporter, kind="sflow", sampling=rate or 1)


# --------------------------------------------------------------------------
# dispatcher
# --------------------------------------------------------------------------

def read(path: str, exporter: str = ""):
    from pathlib import Path
    data = Path(path).read_bytes()
    exporter = exporter or Path(path).name
    store = _TemplateStore()
    pos = 0
    n = len(data)
    produced = False
    while pos + 4 <= n:
        ver = struct.unpack_from(">H", data, pos)[0]
        u32 = struct.unpack_from(">I", data, pos)[0]
        if u32 == 5:                                       # sFlow v5
            for f in _sflow(data[pos:], exporter):
                produced = True
                yield f
            return
        if ver == 5:                                       # NetFlow v5
            count = struct.unpack_from(">H", data, pos + 2)[0]
            reclen = 24 + 48 * count
            for f in _nf5(data[pos:pos + reclen], exporter):
                produced = True
                yield f
            pos += reclen
            continue
        if ver == 9:
            mlen = _nf9_msglen(data, pos)
            for f in _nf9(data[pos:pos + mlen], exporter, store):
                produced = True
                yield f
            pos += mlen
            continue
        if ver == 10:
            mlen = struct.unpack_from(">H", data, pos + 2)[0] or (n - pos)
            for f in _ipfix(data[pos:pos + mlen], exporter, store):
                produced = True
                yield f
            pos += max(mlen, 16)
            continue
        break
    if not produced:
        raise FlowError(f"{path}: not a NetFlow / IPFIX / sFlow export")


def _nf9_msglen(data: bytes, pos: int) -> int:
    """Walk flowsets from the header until one looks invalid (next message)."""
    off = pos + 20
    n = len(data)
    while off + 4 <= n:
        fs_id, fs_len = struct.unpack_from(">HH", data, off)
        if fs_len < 4 or off + fs_len > n or fs_id in (2, 3) or \
                (2 <= fs_id < 256):
            break
        # a new v9/IPFIX header starting here?
        if fs_id in (9, 10) and struct.unpack_from(">H", data, off + 2)[0] < 100:
            break
        off += fs_len
    return max(off - pos, 20)
