"""Aggregate IP<->MAC observations into bindings + conflicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from network_arp import oui
from network_arp import sources as _sources


def _iso(ts):
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + "Z"


@dataclass
class Binding:
    ip: str
    mac: str
    first: float | None = None
    last: float | None = None
    count: int = 0
    hostnames: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    ifaces: set = field(default_factory=set)
    kinds: set = field(default_factory=set)
    notable: list = field(default_factory=list)

    def touch(self, o: "_sources.Obs"):
        self.count += 1
        self.sources.add(o.source)
        if o.hostname:
            self.hostnames.add(o.hostname)
        if o.iface:
            self.ifaces.add(o.iface)
        if o.kind:
            self.kinds.add(o.kind)
        if o.ts is not None:
            self.first = o.ts if self.first is None else min(self.first, o.ts)
            self.last = o.ts if self.last is None else max(self.last, o.ts)

    def row(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac,
            "vendor": oui.vendor(self.mac),
            "hostnames": ",".join(sorted(self.hostnames)),
            "first_seen": _iso(self.first), "last_seen": _iso(self.last),
            "observations": self.count,
            "sources": ",".join(sorted(self.sources)),
            "ifaces": ",".join(sorted(self.ifaces)),
            "kinds": ",".join(sorted(self.kinds)),
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    bindings: list = field(default_factory=list)
    observations: int = 0
    sources: dict = field(default_factory=dict)
    conflicts: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _overlap(a: Binding, b: Binding, *, near: float = 900.0) -> bool:
    """True if the two bindings' time spans overlap or sit within *near*
    seconds of each other (or either span is unknown)."""
    if None in (a.first, a.last, b.first, b.last):
        return True
    if a.first <= b.last and b.first <= a.last:
        return True
    gap = max(a.first, b.first) - min(a.last, b.last)
    return gap <= near


def analyze(paths, *, progress=None) -> Result:
    res = Result()
    table: dict[tuple, Binding] = {}
    for path in paths:
        try:
            for o in _sources.read(path):
                res.observations += 1
                res.sources[o.source] = res.sources.get(o.source, 0) + 1
                if not o.ip or not o.mac or len(o.mac) < 12:
                    continue
                key = (o.ip, o.mac)
                b = table.get(key)
                if b is None:
                    b = table[key] = Binding(ip=o.ip, mac=o.mac)
                b.touch(o)
                if progress and res.observations % 10000 == 0:
                    progress(res.observations)
        except (_sources.ArpError, OSError) as e:
            res.errors.append(str(e))

    binds = list(table.values())
    by_ip: dict[str, list] = {}
    by_mac: dict[str, list] = {}
    for b in binds:
        by_ip.setdefault(b.ip, []).append(b)
        by_mac.setdefault(b.mac, []).append(b)

    for ip, group in by_ip.items():
        macs = {b.mac for b in group}
        if len(macs) > 1:
            # overlapping in time -> conflict / spoofing
            conflicting = any(_overlap(x, y) for i, x in enumerate(group)
                              for y in group[i + 1:])
            for b in group:
                b.notable.append(
                    f"IP {ip} claimed by {len(macs)} MACs"
                    + (" (overlapping in time)" if conflicting else
                       " (sequential - re-assignment)"))
            if conflicting:
                res.conflicts.append(
                    f"{ip}: {', '.join(sorted(macs))} - overlapping bindings")

    for mac, group in by_mac.items():
        ips = {b.ip for b in group}
        if len(ips) >= 5:
            for b in group:
                b.notable.append(
                    f"MAC {mac} bound to {len(ips)} IPs (router / NAT / "
                    f"MAC spoofing?)")

    for b in binds:
        if oui.is_local(b.mac) and not oui.is_multicast(b.mac):
            b.notable.append("locally-administered MAC (randomised / spoofed?)")
        if "gratuitous" in b.kinds:
            b.notable.append("gratuitous ARP announced")

    res.bindings = sorted(binds, key=lambda b: (b.first is None,
                                                b.first or 0.0, b.ip))
    return res
