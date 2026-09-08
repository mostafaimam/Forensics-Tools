"""Graphical viewer for browser_logins (see ``browser_logins --gui``)."""

from __future__ import annotations

from browser_logins.analyze import analyze
from browser_logins.output import row

_COLS = ["date_last_used", "date_created", "date_password_changed", "browser",
         "host", "username", "times_used", "blacklisted", "has_password",
         "scheme", "severity", "notable"]


def run_gui(paths: list[str] | None = None) -> int:
    from browser_logins.guikit import run

    def load(ps):
        res = analyze(list(ps))
        return [row(lg) for lg in res.logins]

    return run("browser_logins - saved-login metadata", load, columns=_COLS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open Login Data / logins.json / folder", multi=True,
               alert_keys=("notable",))
