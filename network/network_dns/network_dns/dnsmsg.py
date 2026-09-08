"""A self-contained DNS message parser (RFC 1035 + common extensions)."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

TYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
        13: "HINFO", 15: "MX", 16: "TXT", 17: "RP", 24: "SIG", 25: "KEY",
        28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 39: "DNAME",
        41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
        50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 59: "CDS", 60: "CDNSKEY",
        64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48", 109: "EUI64",
        249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY",
        256: "URI", 257: "CAA"}
_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
_OPCODE = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}


def type_name(t: int) -> str:
    return TYPE.get(t, f"TYPE{t}")


def rcode_name(r: int) -> str:
    return _RCODE.get(r, f"RCODE{r}")


def _name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    ret = None
    while 0 <= off < len(buf) and depth < 25:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if ret is None:
                ret = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("latin-1", "replace"))
        off += 1 + ln
    name = ".".join(labels) if labels else "."
    return name, (ret if ret is not None else off)


@dataclass
class RR:
    name: str
    rtype: str
    rclass: int
    ttl: int
    value: str


@dataclass
class Message:
    id: int = 0
    is_response: bool = False
    opcode: str = "QUERY"
    rcode: str = "NOERROR"
    flags_aa: bool = False
    flags_tc: bool = False
    flags_rd: bool = False
    flags_ra: bool = False
    questions: list = field(default_factory=list)     # [(name, type)]
    answers: list = field(default_factory=list)       # [RR]
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    edns_udp_size: int | None = None

    @property
    def qname(self) -> str:
        return self.questions[0][0] if self.questions else ""

    @property
    def qtype(self) -> str:
        return self.questions[0][1] if self.questions else ""


def _rdata(buf: bytes, rtype: int, off: int, rdlen: int) -> str:
    end = off + rdlen
    try:
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntop(socket.AF_INET, buf[off:end])
        if rtype == 28 and rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, buf[off:end])
        if rtype in (2, 5, 12, 39):
            return _name(buf, off)[0]
        if rtype == 15:
            pref = struct.unpack_from(">H", buf, off)[0]
            return f"{pref} {_name(buf, off + 2)[0]}"
        if rtype == 33:                                   # SRV
            prio, weight, port = struct.unpack_from(">HHH", buf, off)
            return f"{prio} {weight} {port} {_name(buf, off + 6)[0]}"
        if rtype in (16, 99):                             # TXT / SPF
            out, p = [], off
            while p < end:
                sl = buf[p]
                out.append(buf[p + 1:p + 1 + sl].decode("latin-1", "replace"))
                p += 1 + sl
            return "".join(out)
        if rtype == 6:                                    # SOA
            mname, p = _name(buf, off)
            rname, p = _name(buf, p)
            serial, refresh, retry, expire, minimum = struct.unpack_from(
                ">IIIII", buf, p)
            return f"{mname} {rname} {serial} {minimum}"
        if rtype == 257:                                  # CAA
            flags = buf[off]
            tl = buf[off + 1]
            tag = buf[off + 2:off + 2 + tl].decode("latin-1", "replace")
            val = buf[off + 2 + tl:end].decode("latin-1", "replace")
            return f'{flags} {tag} "{val}"'
        if rtype == 10:                                   # NULL
            return buf[off:end].hex()
    except (struct.error, IndexError, OSError):
        pass
    return buf[off:end][:64].hex()


def parse(payload: bytes) -> Message | None:
    if len(payload) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", payload, 0)
    except struct.error:
        return None
    if qd > 40 or an > 200 or ns > 200 or ar > 200:
        return None
    m = Message(id=tid, is_response=bool(flags & 0x8000),
                opcode=_OPCODE.get((flags >> 11) & 0xF, str((flags >> 11) & 0xF)),
                rcode=rcode_name(flags & 0xF),
                flags_aa=bool(flags & 0x0400), flags_tc=bool(flags & 0x0200),
                flags_rd=bool(flags & 0x0100), flags_ra=bool(flags & 0x0080))
    off = 12
    try:
        for _ in range(qd):
            qn, off = _name(payload, off)
            qt, qc = struct.unpack_from(">HH", payload, off)
            off += 4
            m.questions.append((qn.lower(), type_name(qt)))
        for bucket, count in ((m.answers, an), (m.authority, ns),
                              (m.additional, ar)):
            for _ in range(count):
                rn, off = _name(payload, off)
                rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH",
                                                               payload, off)
                off += 10
                if rtype == 41:                            # OPT / EDNS0
                    m.edns_udp_size = rclass
                    off += rdlen
                    continue
                bucket.append(RR(rn.lower(), type_name(rtype), rclass, ttl,
                                 _rdata(payload, rtype, off, rdlen)))
                off += rdlen
    except (struct.error, IndexError):
        if not m.questions:
            return None
    return m
