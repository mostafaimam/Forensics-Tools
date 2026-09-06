"""Graphical email inventory (see ``analysis_email --gui``)."""
from __future__ import annotations

from analysis_email.cli import _COLUMNS, _iter
from analysis_email.formats import parse_file
from analysis_email.guikit import run


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for f in _iter([str(p) for p in ps], True):
            try:
                for m in parse_file(str(f)):
                    rows.append(m.as_row())
            except (ValueError, OSError, NotImplementedError):
                continue
        return rows

    return run("analysis_email", load, columns=_COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open mail file / folder", alert_keys=("flags",))
