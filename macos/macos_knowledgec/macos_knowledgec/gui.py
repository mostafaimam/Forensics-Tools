"""Graphical viewer for macos_knowledgec."""

from __future__ import annotations

from pathlib import Path

from macos_knowledgec import flags as _flags
from macos_knowledgec.cli import _discover
from macos_knowledgec.parse import parse

_COLS = ["start", "end", "duration_s", "stream", "value", "title",
         "bundle_id", "device_id", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_knowledgec.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for e in parse(str(db)):
                    r = e.row()
                    r["severity"] = _flags.severity(e.notable)
                    rows.append(r)
        return rows

    return run("macos_knowledgec - activity timeline", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open knowledgeC.db", multi=True,
               alert_keys=("notable",))
