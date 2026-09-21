"""Graphical viewer for mobile_android."""

from __future__ import annotations

from mobile_android.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from mobile_android.collect import collect
    from mobile_android.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(collect(str(p)).rows)
        return rows

    return run("mobile_android - adb backup (.ab) inventory", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open an .ab backup file",
              open_is_dir=False, multi=True)
