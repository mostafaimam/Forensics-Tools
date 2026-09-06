"""Graphical deduplication viewer (see ``analysis_dedupe --gui``)."""
from __future__ import annotations

from analysis_dedupe.guikit import run
from analysis_dedupe.scan import scan

COLUMNS = ["path", "size", "digest", "group", "representative", "duplicate_of"]


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        res = scan(list(ps), full=True)
        return [{"path": r.path, "size": r.size, "digest": r.digest,
                 "group": r.group if r.group > 0 else "",
                 "representative": "yes" if r.representative else "",
                 "duplicate_of": r.duplicate_of} for r in res.files]

    return run("analysis_dedupe", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Scan folder", open_is_dir=True,
               alert_keys=("duplicate_of",))
