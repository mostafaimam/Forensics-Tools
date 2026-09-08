"""Aggregate DNS events into per-name records."""

from __future__ import annotations

from dataclasses import dataclass, field

from network_dns import flags as _flags
from network_dns import sources as _sources


@dataclass
class Name:
    qname: str
    sources: set = field(default_factory=set)
    qtypes: set = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None
    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    servfail: int = 0
    resolvers: set = field(default_factory=set)
    clients: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    cnames: set = field(default_factory=set)
    txt: list = field(default_factory=list)
    has_null: bool = False
    truncated: bool = False
    static_ips: set = field(default_factory=set)   # from a hosts file
    answer_ttls: list = field(default_factory=list)
    notable: list = field(default_factory=list)

    def _touch(self, ts):
        if ts is None:
            return
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)

    def add(self, ev: "_sources.Event") -> None:
        self.sources.add(ev.source)
        if ev.qtype:
            self.qtypes.add(ev.qtype)
        self._touch(ev.ts)
        if ev.client:
            self.clients.add(ev.client)
        if ev.server:
            self.resolvers.add(ev.server)
        if ev.truncated:
            self.truncated = True
        if ev.kind == "query":
            self.queries += 1
        elif ev.kind == "response":
            self.responses += 1
            if ev.rcode == "NXDOMAIN":
                self.nxdomain += 1
            elif ev.rcode == "SERVFAIL":
                self.servfail += 1
        elif ev.kind == "static":
            for _t, val, _ttl in ev.answers:
                self.static_ips.add(val)
        for rtype, val, ttl in ev.answers:
            if rtype in ("A", "AAAA"):
                self.ips.add(val)
                if ttl:
                    self.answer_ttls.append(ttl)
            elif rtype == "CNAME":
                self.cnames.add(val)
            elif rtype in ("TXT", "SPF"):
                self.txt.append(val)
            elif rtype == "NULL":
                self.has_null = True

    def row(self) -> dict:
        return {
            "qname": self.qname,
            "sources": ",".join(sorted(self.sources)),
            "qtypes": ",".join(sorted(self.qtypes)),
            "first_seen": _iso(self.first_ts),
            "last_seen": _iso(self.last_ts),
            "queries": self.queries,
            "responses": self.responses,
            "nxdomain": self.nxdomain,
            "servfail": self.servfail,
            "resolvers": ",".join(sorted(self.resolvers)),
            "clients": ",".join(sorted(self.clients)),
            "ips": ",".join(sorted(self.ips)),
            "cnames": ",".join(sorted(self.cnames)),
            "ttl_min": min(self.answer_ttls) if self.answer_ttls else "",
            "ttl_max": max(self.answer_ttls) if self.answer_ttls else "",
            "txt_max_len": max((len(t) for t in self.txt), default=""),
            "hosts_override": ",".join(sorted(self.static_ips)),
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    names: list = field(default_factory=list)
    events: int = 0
    sources: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def _iso(ts):
    if ts is None:
        return ""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + "Z"


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    table: dict[str, Name] = {}
    for path in paths:
        try:
            for ev in _sources.read(path):
                res.events += 1
                res.sources[ev.source] = res.sources.get(ev.source, 0) + 1
                key = ev.qname or "(no name)"
                rec = table.get(key)
                if rec is None:
                    rec = table[key] = Name(qname=key)
                rec.add(ev)
                if progress and res.events % 5000 == 0:
                    progress(res.events)
        except (_sources._pcap.PcapError, OSError) as e:
            res.errors.append(str(e))

    for rec in table.values():
        rec.notable = _flags.flag(rec)
    res.names = sorted(table.values(),
                       key=lambda r: (r.first_ts is None, r.first_ts or 0.0,
                                      r.qname))
    return res
