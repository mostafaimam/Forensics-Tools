"""Graphical viewer for app_chat."""

from __future__ import annotations

from app_chat.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from app_chat.collect import collect
    from app_chat.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(collect(str(p)).rows)
        return rows

    return run("app_chat - chat app message recovery", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a chat app's data folder",
              open_is_dir=True, multi=True, alert_keys=("deleted",))
