"""Graphical viewer for macos_spotlight."""

from __future__ import annotations

from macos_spotlight.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from macos_spotlight.collect import collect
    from macos_spotlight.guikit import run

    def load(ps):
        return collect([str(p) for p in ps]).rows

    return run("macos_spotlight - Spotlight artifact carver", load,
               columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open store.db / .spotlight-V100 folder",
               open_is_dir=True, multi=True)
