"""CSV / JSON / text shaping for windows_srum."""

from __future__ import annotations

import io

from windows_srum import flags as _flags

_BASE_COLS = ["provider", "timestamp", "app", "user", "app_id", "user_id"]
_TAIL_COLS = ["severity", "source", "notable"]


def columns(result) -> list[str]:
    mid = [c for c in result.columns
           if c not in _BASE_COLS and c not in ("source", "notable")]
    return _BASE_COLS + mid + _TAIL_COLS


def row(r) -> dict:
    d = r.row()
    d["severity"] = _flags.severity(r.notable)
    return d


def render(rows) -> str:
    out = io.StringIO()
    by_prov: dict[str, int] = {}
    for r in rows:
        by_prov[r["provider"]] = by_prov.get(r["provider"], 0) + 1
    out.write("providers: " + ", ".join(f"{k}={v}" for k, v in
                                        sorted(by_prov.items())) + "\n\n")
    for r in rows:
        mark = f"  [{r['severity']}]" if r.get("severity", "none") != "none" \
            else ""
        extra = " ".join(f"{k}={v}" for k, v in r.items()
                         if k not in (*_BASE_COLS, *_TAIL_COLS)
                         and v not in (None, "", 0))
        out.write(f"{r['timestamp'] or '(no time)':<20} {r['provider']:<22} "
                  f"{r['app']}{mark}\n")
        if extra:
            out.write(f"    {extra}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
    return out.getvalue()
