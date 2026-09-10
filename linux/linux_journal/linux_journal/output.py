"""CSV / JSON / text shaping for linux_journal."""

from __future__ import annotations

import io

from linux_journal import flags as _flags

# the columns that matter for a review; the full field dict also goes to JSON
COLUMNS = ["ts", "monotonic_us", "boot_id", "priority", "unit", "comm", "pid",
           "uid", "transport", "hostname", "message", "severity", "notable"]

_PRIO = _flags._PRIO_NAME


def row(e) -> dict:
    f = e.fields
    notable = getattr(e, "notable", None)
    if notable is None:
        notable = _flags.flag(e)
    prio = f.get("PRIORITY", "")
    return {
        "ts": e.iso,
        "monotonic_us": e.monotonic_us or "",
        "boot_id": e.boot_id,
        "priority": _PRIO.get(prio, prio),
        "unit": f.get("_SYSTEMD_UNIT", "") or f.get("UNIT", ""),
        "comm": f.get("_COMM", ""),
        "pid": f.get("_PID", ""),
        "uid": f.get("_UID", ""),
        "transport": f.get("_TRANSPORT", ""),
        "hostname": f.get("_HOSTNAME", ""),
        "message": f.get("MESSAGE", ""),
        "severity": _flags.severity(notable),
        "notable": ";".join(notable),
    }


def record(e) -> dict:
    """Full record for JSON: the shaped row plus every raw field."""
    r = row(e)
    r["fields"] = dict(e.fields)
    return r


def render(rows, boots=None, warnings=None) -> str:
    out = io.StringIO()
    if boots:
        out.write("boots:\n")
        for bid, (lo, hi) in boots.items():
            out.write(f"  {bid}  {lo}  ..  {hi}\n")
        out.write("\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        who = r["unit"] or r["comm"] or r["transport"] or "-"
        out.write(f"{r['ts'] or '(no time)':<28} {r['priority'][:7]:<7} "
                  f"{who}: {r['message']}{mark}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    if warnings:
        out.write("\nwarnings:\n")
        for w in warnings:
            out.write(f"  * {w}\n")
    return out.getvalue()
