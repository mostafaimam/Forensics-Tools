"""Best-effort application-layer extraction: DNS and HTTP."""

from __future__ import annotations

import struct

_DNS_TYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
             48: "DNSKEY", 65: "HTTPS", 64: "SVCB", 257: "CAA"}
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"CONNECT ", b"TRACE ")


def _name(buf: bytes, off: int, depth: int = 0):
    labels = []
    jumped_at = None
    while depth < 20 and 0 <= off < len(buf):
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if jumped_at is None:
                jumped_at = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("idna", "replace")
                      if False else
                      buf[off + 1:off + 1 + ln].decode("latin-1", "replace"))
        off += 1 + ln
    return ".".join(labels), (jumped_at if jumped_at is not None else off)


def parse_dns(payload: bytes):
    """Return a dict, or None."""
    if len(payload) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", payload, 0)
    except struct.error:
        return None
    is_resp = bool(flags & 0x8000)
    rcode = flags & 0x0F
    if qd == 0 or qd > 20 or an > 100:
        return None
    off = 12
    queries = []
    try:
        for _ in range(qd):
            qname, off = _name(payload, off)
            qtype, qclass = struct.unpack_from(">HH", payload, off)
            off += 4
            queries.append((qname, _DNS_TYPE.get(qtype, str(qtype))))
        answers = []
        for _ in range(an):
            rname, off = _name(payload, off)
            rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", payload, off)
            off += 10
            rdata = payload[off:off + rdlen]
            off += rdlen
            val = ""
            import socket
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (2, 5, 12):
                val, _ = _name(payload, off - rdlen)
            elif rtype == 16 and rdlen:
                val = rdata[1:1 + rdata[0]].decode("latin-1", "replace")
            answers.append((_DNS_TYPE.get(rtype, str(rtype)), val))
    except (struct.error, IndexError, OSError):
        if not queries:
            return None
        answers = []
    return {
        "id": tid, "response": is_resp, "rcode": rcode,
        "queries": queries, "answers": answers,
        "answer_count": an,
    }


def parse_http(payload: bytes):
    if not payload:
        return None
    head = payload[:2048]
    lines = head.split(b"\r\n")
    first = lines[0] if lines else b""
    out = {}
    if any(first.startswith(m) for m in _HTTP_METHODS):
        try:
            method, target, ver = first.split(b" ", 2)
        except ValueError:
            return None
        out["kind"] = "request"
        out["method"] = method.decode("latin-1")
        out["target"] = target.decode("latin-1", "replace")[:400]
        out["version"] = ver.decode("latin-1", "replace")
    elif first.startswith(b"HTTP/"):
        parts = first.split(b" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        out["kind"] = "response"
        out["status"] = int(parts[1])
        out["reason"] = (parts[2].decode("latin-1", "replace")
                         if len(parts) > 2 else "")
    else:
        return None
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        kl = k.strip().lower()
        vs = v.strip().decode("latin-1", "replace")
        if kl == b"host":
            out["host"] = vs[:255]
        elif kl == b"user-agent":
            out["user_agent"] = vs[:255]
        elif kl == b"authorization":
            out["authorization"] = vs[:120]
        elif kl == b"content-type":
            out["content_type"] = vs[:120]
        elif kl == b"referer":
            out["referer"] = vs[:400]
        elif kl == b"server":
            out["server"] = vs[:120]
        elif kl == b"location":
            out["location"] = vs[:400]
    # a form body on a request
    body_at = head.find(b"\r\n\r\n")
    if out.get("kind") == "request" and body_at != -1:
        body = head[body_at + 4:body_at + 400]
        if b"password" in body.lower() or b"passwd" in body.lower() \
                or b"&pass" in body.lower():
            out["body_has_password_field"] = True
        if body:
            out["body_preview"] = body.decode("latin-1", "replace")[:200]
    return out
