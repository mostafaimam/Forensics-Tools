"""The merged table plus a review sidecar (tags / notes / reviewed)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from analysis_view.reader import load


def row_id(source: str, index: int, row: dict) -> str:
    h = hashlib.sha1()
    h.update(source.encode())
    h.update(str(index).encode())
    h.update("\x1f".join(f"{k}={row[k]}" for k in sorted(row)).encode(
        "utf-8", "replace"))
    return h.hexdigest()[:16]


@dataclass
class Review:
    tags: dict[str, list[str]] = field(default_factory=dict)     # rid -> [tag]
    notes: dict[str, str] = field(default_factory=dict)          # rid -> note
    reviewed: set[str] = field(default_factory=set)              # rid
    tag_colors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "Review":
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        return cls(
            tags={k: list(v) for k, v in (d.get("tags") or {}).items()},
            notes=dict(d.get("notes") or {}),
            reviewed=set(d.get("reviewed") or []),
            tag_colors=dict(d.get("tag_colors") or {}))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({
            "tags": self.tags, "notes": self.notes,
            "reviewed": sorted(self.reviewed),
            "tag_colors": self.tag_colors,
        }, indent=2), encoding="utf-8")

    def all_tags(self) -> list[str]:
        s = set()
        for v in self.tags.values():
            s.update(v)
        return sorted(s)


@dataclass
class Table:
    rows: list[dict] = field(default_factory=list)      # each has "_id",
    #                                                     "_source" injected
    columns: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @classmethod
    def from_paths(cls, paths, *, delim=None, sheet=None) -> "Table":
        t = cls()
        for raw in paths:
            src = Path(raw).name
            recs, cols = load(raw, delim=delim, sheet=sheet)
            t.sources.append(src)
            for c in cols:
                if c not in t.columns:
                    t.columns.append(c)
            for i, r in enumerate(recs):
                rid = row_id(src, i, r)
                out = {"_id": rid, "_source": src}
                out.update({c: r.get(c, "") for c in cols})
                t.rows.append(out)
        # ensure every row has every column key
        allcols = t.columns
        for r in t.rows:
            for c in allcols:
                r.setdefault(c, "")
        return t

    def display_columns(self) -> list[str]:
        cols = list(self.columns)
        if len(self.sources) > 1 and "_source" not in cols:
            cols = ["_source"] + cols
        return cols
