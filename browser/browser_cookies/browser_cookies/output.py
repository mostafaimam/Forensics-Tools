"""Row shaping and CSV / JSON writers (CSV-injection safe, UTF-8 BOM)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from browser_cookies import flags as _flags

COLUMNS = ["host", "name", "path", "browser", "profile", "created",
           "last_access", "expires", "session", "secure", "http_only",
           "samesite", "value_len", "notable", "severity", "source_db"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def row(cookie, with_values: bool = False) -> dict:
    r = cookie.row(with_values)
    r["severity"] = _flags.severity(cookie.notable)
    return r


def columns(with_values: bool) -> list[str]:
    return (COLUMNS[:13] + ["value"] + COLUMNS[13:]) if with_values else COLUMNS


def write_csv(rows, path: Path, with_values: bool = False) -> None:
    cols = columns(with_values)
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in cols})


def write_json(rows, path: Path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render(rows) -> str:
    out = io.StringIO()
    last_host = None
    for r in rows:
        if r["host"] != last_host:
            out.write(f"\n{r['host']}\n")
            last_host = r["host"]
        flags = []
        if r["secure"]:
            flags.append("Secure")
        if r["http_only"]:
            flags.append("HttpOnly")
        if r["samesite"] not in ("unspecified", "none"):
            flags.append(f"SameSite={r['samesite']}")
        if r["session"]:
            flags.append("session")
        exp = f"exp {r['expires'][:10]}" if r["expires"] else "session"
        mark = f"  [{r['severity']}] {r['notable']}" if r["notable"] else ""
        out.write(f"  {r['name']:<28} {r['path']:<12} {exp:<16} "
                  f"{' '.join(flags)}{mark}\n")
    return out.getvalue()
