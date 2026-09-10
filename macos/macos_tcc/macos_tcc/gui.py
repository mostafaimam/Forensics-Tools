"""Graphical viewer for macos_tcc."""

from __future__ import annotations

from pathlib import Path

from macos_tcc import flags as _flags
from macos_tcc.cli import _discover
from macos_tcc.parse import parse

_COLS = ["scope", "decision", "service", "client", "client_type",
         "indirect_object", "auth_reason", "last_modified", "from_profile",
         "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_tcc.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for db, scope in _discover(Path(p)):
                for g in parse(str(db), scope):
                    r = g.row()
                    r["severity"] = _flags.severity(g.notable)
                    rows.append(r)
        return rows

    return run("macos_tcc - privacy permissions", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open TCC.db", multi=True, alert_keys=("notable",))
