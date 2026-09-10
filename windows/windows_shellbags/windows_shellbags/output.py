"""CSV / JSON / text shaping for windows_shellbags."""

from __future__ import annotations

import io

from windows_shellbags import flags as _flags

COLUMNS = ["path", "name", "item_type", "guid", "depth", "mru_position",
           "last_interacted", "created", "modified", "accessed", "mft_entry",
           "mft_sequence", "node_slot", "key_path", "source", "severity",
           "notable"]


def row(b) -> dict:
    r = b.row()
    r["severity"] = _flags.severity(b.notable)
    return r


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        indent = "  " * r["depth"]
        out.write(f"{indent}{r['path'] or r['name'] or '(unnamed)'}  "
                  f"<{r['item_type']}>{mark}\n")
        times = []
        if r["last_interacted"]:
            times.append(f"interacted {r['last_interacted']}")
        if r["modified"]:
            times.append(f"modified {r['modified']}")
        if r["created"]:
            times.append(f"created {r['created']}")
        if times:
            out.write(f"{indent}    {'  '.join(times)}\n")
        if r["mft_entry"]:
            out.write(f"{indent}    $MFT {r['mft_entry']}"
                      f"-{r['mft_sequence']}\n")
        for n in r["notable"].split(";") if r["notable"] else []:
            out.write(f"{indent}    ! {n}\n")
    return out.getvalue()
