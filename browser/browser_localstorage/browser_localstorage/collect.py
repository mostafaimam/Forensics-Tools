"""Tie the LevelDB engine + Local Storage schema together for CLI/GUI use."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from browser_localstorage import localstorage, store

COLUMNS = ["store_kind", "origin", "key", "value", "deleted", "sequence",
          "engine", "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _generic_text(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if text.isprintable() or enc != "latin-1":
            return text
    return raw.hex()


def _classify(path: Path) -> str:
    low = str(path).lower()
    if "local storage" in low:
        return "local_storage"
    if "indexeddb" in low or "indexed db" in low:
        return "indexeddb"
    return "leveldb"


def collect(targets: list[str]) -> Result:
    res = Result()
    dirs: list[Path] = []
    for t in targets:
        dirs.extend(store.find_dirs(t))
    if not dirs:
        res.warnings.append("no LevelDB directory (.log/.ldb) found")
        return res
    for d in dirs:
        kind = _classify(d)
        try:
            records = store.read_dir(d)
        except OSError as e:
            res.warnings.append(f"{d}: {e}")
            continue
        for r in records:
            if kind == "local_storage":
                entry = localstorage.decode(r.key, r.value)
                res.rows.append({
                    "store_kind": kind, "origin": entry.origin,
                    "key": entry.key, "value": entry.value,
                    "deleted": r.deleted, "sequence": r.sequence,
                    "engine": r.kind, "source": r.source,
                })
            else:
                res.rows.append({
                    "store_kind": kind, "origin": "",
                    "key": _generic_text(r.key),
                    "value": _generic_text(r.value),
                    "deleted": r.deleted, "sequence": r.sequence,
                    "engine": r.kind, "source": r.source,
                })
    return res
