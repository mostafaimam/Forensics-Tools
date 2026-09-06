from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from macos_plist.flatten import flatten, json_safe

FLAT_COLUMNS = ["source_file", "format", "keyed_archive", "key_path", "value",
                "parse_error"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def flat_rows(loaded_list):
    """loaded_list: iterable of (LoadedPlist, resolved_value)."""
    for lp, value in loaded_list:
        if lp.parse_error:
            yield {
                "source_file": lp.source, "format": lp.fmt,
                "keyed_archive": "yes" if lp.is_keyed_archive else "no",
                "key_path": "", "value": "", "parse_error": lp.parse_error,
            }
            continue
        for path, val in flatten(value).items():
            yield {
                "source_file": lp.source, "format": lp.fmt,
                "keyed_archive": "yes" if lp.is_keyed_archive else "no",
                "key_path": path, "value": val, "parse_error": "",
            }


def write_csv(rows, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FLAT_COLUMNS, dialect="excel")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(v) for k, v in r.items()})


def write_json(loaded_list, path: Path) -> None:
    out = []
    for lp, value in loaded_list:
        out.append({
            "source_file": lp.source,
            "format": lp.fmt,
            "keyed_archive": lp.is_keyed_archive,
            "parse_error": lp.parse_error or None,
            "value": json_safe(value) if not lp.parse_error else None,
        })
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False),
                    encoding="utf-8")


def render(loaded_list, limit: int = 400) -> str:
    out = io.StringIO()
    for lp, value in loaded_list:
        out.write(f"# {lp.source}  ({lp.fmt}"
                  f"{', keyed archive' if lp.is_keyed_archive else ''})\n")
        if lp.parse_error:
            out.write(f"  [ERROR] {lp.parse_error}\n\n")
            continue
        rows = flatten(value)
        for i, (path, val) in enumerate(rows.items()):
            if i >= limit:
                out.write(f"  ... {len(rows) - limit} more\n")
                break
            v = val if len(val) <= 120 else val[:119] + "…"
            out.write(f"  {path} = {v}\n")
        out.write("\n")
    return out.getvalue()
