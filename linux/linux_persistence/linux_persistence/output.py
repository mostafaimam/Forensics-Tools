"""CSV / JSON / text shaping for linux_persistence."""

from __future__ import annotations

import io

COLUMNS = ["mechanism", "path", "line", "payload", "mtime", "owner_uid",
           "world_writable", "verdict", "why"]


def row(f) -> dict:
    return f.row()


def render(res) -> str:
    out = io.StringIO()
    by_mech: dict[str, list] = {}
    for f in res.findings:
        by_mech.setdefault(f.mechanism, []).append(f)
    tally = ", ".join(f"{k}:{len(v)}" for k, v in sorted(by_mech.items()))
    out.write(f"persistence sweep: {len(res.findings)} finding(s) across "
              f"{len(res.files_seen)} file(s)\n")
    if tally:
        out.write(f"  by mechanism: {tally}\n")
    out.write("\n")
    for f in res.findings:
        out.write(f"[{f.verdict:^6}] {f.mechanism:<20} {f.path}"
                  f"{(':' + str(f.line_no)) if f.line_no else ''}\n")
        if f.payload:
            out.write(f"          {f.payload}\n")
        for w in f.why:
            out.write(f"          ! {w}\n")
    for e in res.errors:
        out.write(f"\n  error: {e}\n")
    return out.getvalue()
