"""CSV / JSON / text output for browser_cache."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

COLUMNS = ["response_time", "last_fetched", "browser", "profile", "cache",
           "method", "status", "url", "content_type", "content_encoding",
           "declared_length", "body_size", "request_time", "expires",
           "last_modified", "server", "etag", "fetch_count", "entry_file",
           "sha256", "saved_as", "truncated", "severity", "notable"]

_SEV = {
    "cached response body is an executable": "high",
    "content-type / body mismatch": "high",
    "cached URL is an executable": "medium",
    "cached from a raw IP host": "medium",
    "cached archive": "low",
    "large cached script": "low",
    "body shorter than Content-Length": "low",
}


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _severity(notable):
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top


def row(e) -> dict:
    r = e.row()
    r["severity"] = _severity(e.notable)
    return r


def write_csv(rows, path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in COLUMNS})


def write_json(rows, path) -> None:
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def _sz(n) -> str:
    n = int(n or 0)
    for u in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}T"


def render(rows) -> str:
    out = io.StringIO()
    for r in rows:
        mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
        when = r["response_time"] or r["last_fetched"] or "(no time)"
        st = f" {r['status']}" if r["status"] else ""
        out.write(f"{when:<21} {r['browser'] or '-':<7}{st} {r['url']}{mark}\n")
        line = f"    {r['content_type'] or '?'}  {_sz(r['body_size'])}"
        if r["content_encoding"]:
            line += f"  [{r['content_encoding']}]"
        if r["saved_as"]:
            line += f"  -> {r['saved_as']}"
        out.write(line + "\n")
        if r["sha256"]:
            out.write(f"    sha256 {r['sha256']}\n")
        if r["notable"]:
            out.write("    ! " + ", ".join(r["notable"].split(";")) + "\n")
        out.write("\n")
    return out.getvalue()
