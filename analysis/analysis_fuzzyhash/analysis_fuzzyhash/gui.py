"""Graphical viewer for analysis_fuzzyhash."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from analysis_fuzzyhash.guikit import run
    from analysis_fuzzyhash.scan import scan

    def load(ps):
        res = scan([str(p) for p in ps])
        return [it.row() for it in res.items]

    return run("analysis_fuzzyhash - similarity clusters", load,
               columns=["path", "size", "cluster", "representative",
                        "best_match", "best_score", "ctph", "imphash",
                        "is_pe"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open folder", open_is_dir=True, multi=True,
               alert_keys=("cluster",))
