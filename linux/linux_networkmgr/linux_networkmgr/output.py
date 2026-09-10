"""CSV / JSON / text shaping for linux_networkmgr."""

from __future__ import annotations

import io

from linux_networkmgr import flags as _flags

COLUMNS = ["kind", "name", "conn_type", "uuid", "autoconnect", "last_used",
           "ssid", "bssid", "security", "secret_stored", "mac", "cloned_mac",
           "ipv4_method", "addresses", "gateway", "dns", "routes", "proxy",
           "vpn_service", "vpn_gateway", "detail", "severity", "source",
           "notable"]


def row(it) -> dict:
    r = it.row()
    r["severity"] = _flags.severity(it.notable)
    return r


def render(rows) -> str:
    out = io.StringIO()
    by_kind: dict[str, list] = {}
    for r in rows:
        by_kind.setdefault(r["kind"], []).append(r)
    for kind, items in by_kind.items():
        out.write(f"{kind} ({len(items)}):\n")
        for r in items:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            bits = [b for b in (r["name"], r["conn_type"], r["security"],
                                r["addresses"] or r["ipv4_method"],
                                ("dns " + r["dns"]) if r["dns"] else "",
                                r["last_used"]) if b]
            out.write("  " + "  ".join(bits) + mark + "\n")
            for n in r["notable"].split(";") if r["notable"] else []:
                out.write(f"      ! {n}\n")
        out.write("\n")
    return out.getvalue()
