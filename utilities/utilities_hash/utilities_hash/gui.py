"""Graphical viewer for utilities_hash."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from utilities_hash.guikit import run
    from utilities_hash.hashing import hash_all

    def load(ps):
        res = hash_all([str(p) for p in ps], ["sha256"])
        return [{"path": f.rel or f.path, "size": f.size, "mtime": f.mtime,
                 "sha256": f.digests.get("sha256", ""), "error": f.error}
                for f in res.files]

    return run("utilities_hash - file hashes", load,
               columns=["path", "size", "mtime", "sha256", "error"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open folder", open_is_dir=True, multi=True)
