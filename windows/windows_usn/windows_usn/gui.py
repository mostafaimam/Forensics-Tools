"""Graphical viewer for windows_usn (see ``windows_usn --gui``)."""

from __future__ import annotations

from windows_usn import usnparse as _u
from windows_usn.analyze import analyze, severity

_COLS = ["ts", "op", "name", "old_name", "path", "file_entry", "parent_entry",
         "reasons", "attributes", "carved", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_usn.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            recs = list(_u.iter_sequential(data)) or list(_u.iter_carved(data))
            for o in analyze(recs).operations:
                r = o.row()
                r["severity"] = severity(o.notable)
                rows.append(r)
        return rows

    return run("windows_usn - $UsnJrnl:$J", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a $J stream", multi=True,
               alert_keys=("notable",))
