"""Graphical KFF scanner (see ``analysis_kff --gui``)."""
from __future__ import annotations

from analysis_kff.guikit import run
from analysis_kff.output import COLUMNS, row_dict
from analysis_kff.scan import scan_paths
from analysis_kff.store import KFFStore


def run_gui(db: str | None = None, paths: list[str] | None = None) -> int:
    store = KFFStore(db)

    def load(ps):
        return [row_dict(h) for h in scan_paths(store, list(ps))]

    return run("analysis_kff — Known File Filter", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Scan folder", open_is_dir=True,
               alert_keys=("status",))
