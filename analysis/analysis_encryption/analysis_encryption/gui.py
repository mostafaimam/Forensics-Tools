"""Graphical encrypted-file detector (see ``analysis_encryption --gui``)."""
from __future__ import annotations

from pathlib import Path

from analysis_encryption.cli import _iter
from analysis_encryption.detect import analyse
from analysis_encryption.guikit import run

COLUMNS = ["path", "size", "verdict", "scheme", "detail", "entropy"]


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for f in _iter([str(p) for p in ps], True, False, []):
            fnd = analyse(str(f))
            rows.append({"path": fnd.path, "size": fnd.size,
                         "verdict": fnd.verdict, "scheme": fnd.scheme,
                         "detail": fnd.detail, "entropy": fnd.entropy})
        return rows

    return run("analysis_encryption", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Scan folder", open_is_dir=True,
               alert_keys=("verdict",))
