"""CSV / JSON export of the (optionally filtered) view + review sidecar."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def export_csv(rows, columns, path, review=None) -> None:
    cols = list(columns)
    extra = []
    if review is not None:
        extra = ["tags", "note", "reviewed"]
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols + extra)
        for r in rows:
            line = [_san(r.get(c, "")) for c in cols]
            if review is not None:
                rid = r.get("_id", "")
                line += [_san("|".join(review.tags.get(rid, []))),
                         _san(review.notes.get(rid, "")),
                         "yes" if rid in review.reviewed else ""]
            w.writerow(line)


def export_json(rows, columns, path, review=None) -> None:
    out = []
    for r in rows:
        rec = {c: r.get(c, "") for c in columns}
        if review is not None:
            rid = r.get("_id", "")
            rec["_tags"] = review.tags.get(rid, [])
            rec["_note"] = review.notes.get(rid, "")
            rec["_reviewed"] = rid in review.reviewed
        out.append(rec)
    Path(path).write_text(json.dumps(out, indent=2), encoding="utf-8")


def render_table(rows, columns, limit=200) -> str:
    import io
    cols = [c for c in columns if c != "_id"][:8]
    widths = {c: len(c) for c in cols}
    disp = []
    for r in rows[:limit]:
        d = {c: str(r.get(c, ""))[:40] for c in cols}
        disp.append(d)
        for c in cols:
            widths[c] = max(widths[c], len(d[c]))
    out = io.StringIO()
    out.write("  ".join(c.ljust(widths[c]) for c in cols) + "\n")
    out.write("  ".join("-" * widths[c] for c in cols) + "\n")
    for d in disp:
        out.write("  ".join(d[c].ljust(widths[c]) for c in cols) + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more rows\n")
    return out.getvalue()
