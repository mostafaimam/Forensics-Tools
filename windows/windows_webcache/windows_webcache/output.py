"""CSV / JSON / text shaping for windows_webcache."""

from __future__ import annotations

import io

from windows_webcache import flags as _flags

COLUMNS = ["container", "entry_type", "url", "filename", "size",
           "access_count", "modified", "accessed", "expiry", "sync",
           "severity", "source", "notable"]


def row(e) -> dict:
    r = e.row()
    r["severity"] = _flags.severity(e.notable)
    return r


def render(rows) -> str:
    out = io.StringIO()
    by_type: dict[str, int] = {}
    for r in rows:
        by_type[r["entry_type"]] = by_type.get(r["entry_type"], 0) + 1
    out.write("entries: " + ", ".join(f"{k}={v}" for k, v in
                                      sorted(by_type.items())) + "\n\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        when = r["accessed"] or r["modified"] or "(no time)"
        out.write(f"{when:<26} {r['entry_type']:<9} {r['url']}{mark}\n")
        if r["filename"]:
            out.write(f"    file: {r['filename']}  "
                      f"({r['size']} bytes, {r['access_count']}x)\n")
        for n in r["notable"].split(";") if r["notable"] else []:
            out.write(f"    ! {n}\n")
    return out.getvalue()
