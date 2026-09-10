"""Graphical viewer for windows_sum."""

from __future__ import annotations

from windows_sum import flags as _flags

_COLS = ["last_seen", "first_seen", "role", "user", "client_name",
         "address", "total_accesses", "total_seconds", "daily", "severity",
         "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from windows_sum.analyze import analyze
    from windows_sum.guikit import run

    def load(ps):
        rows = []
        for a in analyze([str(p) for p in ps]).rows:
            n, s = _flags.classify(a)
            a.notable = n
            r = a.row()
            r["severity"] = s
            rows.append(r)
        return rows

    return run("windows_sum - User Access Logging", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open SUM folder / .mdb", open_is_dir=True,
               multi=True, alert_keys=("notable",))
