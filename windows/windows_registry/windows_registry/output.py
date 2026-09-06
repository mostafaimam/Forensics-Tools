from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from windows_registry.hive import RegistryHive, to_text, type_name

DUMP_COLUMNS = ["key_path", "key_last_written_utc", "value_name", "value_type",
                "value_data", "deleted"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


def iter_dump_rows(hive: RegistryHive, keys):
    for k in keys:
        vals = k.values()
        if not vals:
            yield {
                "key_path": k.path, "key_last_written_utc": _iso(k.last_written),
                "value_name": "", "value_type": "", "value_data": "",
                "deleted": "yes" if k.deleted else "no",
            }
        for v in vals:
            yield {
                "key_path": k.path,
                "key_last_written_utc": _iso(k.last_written),
                "value_name": v.name,
                "value_type": v.type_name,
                "value_data": to_text(v.data),
                "deleted": "yes" if k.deleted else "no",
            }


def write_dump_csv(rows, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=DUMP_COLUMNS, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(v) for k, v in r.items()})


def write_json(rows, path: Path) -> None:
    rows = list(rows)
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False,
                               default=str), encoding="utf-8")


def write_plugin_csv(rows: list[dict], path: Path) -> None:
    rows = list(rows)
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, dialect="excel",
                           extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in cols})


def render_key(hive: RegistryHive, key) -> str:
    out = io.StringIO()
    out.write(f"{key.path}\n")
    out.write(f"  last written : {_iso(key.last_written)}\n")
    out.write(f"  subkeys      : {key.node.subkey_count}\n")
    out.write(f"  values       : {key.node.value_count}\n")
    for v in key.values():
        out.write(f"    {v.name:<32} {v.type_name:<20} {to_text(v.data)[:100]}\n")
    subs = list(key.subkeys())
    if subs:
        out.write("  subkeys:\n")
        for s in subs:
            out.write(f"    {s.name}\n")
    return out.getvalue()


def render_table(rows, limit: int = 200) -> str:
    rows = list(rows)
    out = io.StringIO()
    cols = [("key_path", 55), ("value_name", 24), ("value_type", 16),
            ("value_data", 40)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 120 + "\n")
    for r in rows[:limit]:
        out.write("  ".join(
            (str(r.get(h, ""))[: w - 1] + "…") if len(str(r.get(h, ""))) > w
            else str(r.get(h, "")).ljust(w) for h, w in cols).rstrip() + "\n")
    if len(rows) > limit:
        out.write(f"... {len(rows) - limit} more (use --csv)\n")
    return out.getvalue()
