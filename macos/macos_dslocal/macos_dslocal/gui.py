"""Graphical viewer for macos_dslocal."""

from __future__ import annotations

from macos_dslocal import flags as _flags
from macos_dslocal.parse import collect

_COLS = ["uid", "name", "realname", "home", "shell", "auth",
         "pbkdf2_iterations", "created", "last_login", "password_last_set",
         "groups", "is_admin", "hint", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from macos_dslocal.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            for u in collect(str(p)).users:
                r = u.row()
                r["severity"] = _flags.severity(u.notable)
                rows.append(r)
        return rows

    return run("macos_dslocal - local accounts", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open a macOS volume or dslocal node", multi=True,
               open_is_dir=True, alert_keys=("notable",))
