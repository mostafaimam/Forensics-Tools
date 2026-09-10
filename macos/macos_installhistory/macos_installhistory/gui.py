"""Graphical viewer for macos_installhistory."""

from __future__ import annotations

from macos_installhistory import flags as _flags
from macos_installhistory.parse import collect

_COLS = ["date", "kind", "name", "version", "process", "content_type",
         "pkg_file", "correlated", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_installhistory.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for rec in collect(str(p)).records:
                r = rec.row()
                r["severity"] = _flags.severity(rec.notable)
                rows.append(r)
        return rows

    return run("macos_installhistory - installed packages", load,
               columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a macOS volume", multi=True,
               open_is_dir=True, alert_keys=("notable",))
