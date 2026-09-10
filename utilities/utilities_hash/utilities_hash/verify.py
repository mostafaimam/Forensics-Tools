"""Load a prior manifest and diff a fresh scan against it."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

_HASH_KEYS = ("sha256", "sha1", "md5", "sha512", "sha3_256", "blake2b")


def load_manifest(path: str) -> dict[str, dict]:
    """Return {rel_path: {size, mtime, <algo>: hex, ...}}."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    out: dict[str, dict] = {}

    if text.lstrip()[:1] in ("[", "{"):
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("files", [])
        for r in rows:
            key = r.get("path") or r.get("rel") or r.get("name")
            if key:
                out[key] = {k: v for k, v in r.items() if k != "path"}
        return out

    # CSV with a header?
    sample = text.splitlines()[:1]
    if sample and ("," in sample[0]) and any(
            h in sample[0].lower() for h in ("path", "sha", "md5")):
        rdr = csv.DictReader(text.splitlines())
        for r in rdr:
            key = r.get("path") or r.get("rel") or r.get("name")
            if key:
                out[key] = {k: v for k, v in r.items() if k and k != "path"}
        return out

    # plain "<hash>  <path>" (coreutils *sum format)
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        h, name = parts[0].strip(), parts[1].strip().lstrip("*")
        algo = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(
            len(h), "sha256")
        out[name] = {algo: h.lower()}
    return out


@dataclass
class Diff:
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)     # (path, old, new, algo)
    moved: list = field(default_factory=list)       # (old_path, new_path, h)
    unchanged: int = 0


def _pick_hash(d: dict) -> tuple[str, str]:
    for a in _HASH_KEYS:
        if d.get(a):
            return a, str(d[a]).lower()
    return "", ""


def diff(manifest: dict[str, dict], result) -> Diff:
    out = Diff()
    fresh = {(f.rel or f.path): f for f in result.files}

    old_by_hash: dict[str, str] = {}
    for path, meta in manifest.items():
        _a, h = _pick_hash(meta)
        if h:
            old_by_hash.setdefault(h, path)

    for path, meta in manifest.items():
        algo, old_h = _pick_hash(meta)
        if path not in fresh:
            out.removed.append(path)
            continue
        f = fresh[path]
        new_h = f.digests.get(algo, "")
        if not new_h:
            _a2, new_h = _pick_hash(f.digests)
            algo = _a2 or algo
        if old_h and new_h and old_h != new_h:
            out.changed.append((path, old_h, new_h, algo))
        else:
            out.unchanged += 1

    seen_moved = set()
    for path, f in fresh.items():
        if path in manifest:
            continue
        _a, h = _pick_hash(f.digests)
        src = old_by_hash.get(h)
        if src and src not in fresh and src not in seen_moved:
            out.moved.append((src, path, h))
            seen_moved.add(src)
        else:
            out.added.append(path)
    # a "moved" source also appears in removed above; prune it
    moved_srcs = {m[0] for m in out.moved}
    out.removed = [r for r in out.removed if r not in moved_srcs]
    return out
