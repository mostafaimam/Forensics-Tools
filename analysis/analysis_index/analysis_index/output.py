from __future__ import annotations

import csv
import io
import json
from pathlib import Path


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def hit_rows(hits):
    for h in hits:
        yield {"path": h.path, "score": h.score, "matches": h.matches,
               "kind": h.kind, "size": h.size,
               "snippet": " ||| ".join(h.snippets)}


def write_csv(rows, path: Path) -> None:
    rows = list(rows)
    cols = ["path", "score", "matches", "kind", "size", "snippet"]
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in cols})


def write_json(rows, path: Path) -> None:
    path.write_text(json.dumps(list(rows), indent=2, default=str),
                    encoding="utf-8")


def render(hits, *, show_snippets=True) -> str:
    out = io.StringIO()
    if not hits:
        return "no matches\n"
    for i, h in enumerate(hits, 1):
        out.write(f"{i:>3}. [{h.score:>7.2f}]  {h.path}"
                  f"   ({h.matches} match{'es' if h.matches != 1 else ''}, "
                  f"{h.kind})\n")
        if show_snippets:
            for s in h.snippets:
                out.write(f"       {s}\n")
    return out.getvalue()
