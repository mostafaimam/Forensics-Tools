"""Graphical gallery inventory (see ``analysis_gallery gui``)."""

from __future__ import annotations

from analysis_gallery.guikit import run
from analysis_gallery.output import COLUMNS, row
from analysis_gallery.scan import scan


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = scan(list(ps), phash_on=True, want_thumbs=False,
                   hash_files=True)
        return [row(f) for f in res.files]

    return run("analysis_gallery — pictures & videos", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Scan folder", open_is_dir=True,
               alert_keys=("gps_lat",))
