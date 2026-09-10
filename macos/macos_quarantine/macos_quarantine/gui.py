"""Graphical viewer for macos_quarantine."""

from __future__ import annotations

from pathlib import Path

from macos_quarantine import flags as _flags
from macos_quarantine.cli import _discover
from macos_quarantine.parse import parse

_COLS = ["timestamp", "agent_name", "data_url", "origin_url", "origin_title",
         "sender_name", "event_type", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_quarantine.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db in _discover(Path(p)):
                for e in parse(str(db)):
                    r = e.row()
                    r["severity"] = _flags.severity(e.notable)
                    rows.append(r)
        return rows

    return run("macos_quarantine - download provenance", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open QuarantineEventsV2", multi=True,
               alert_keys=("notable",))
