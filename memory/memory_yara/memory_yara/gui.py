"""Graphical viewer for memory_yara."""

from __future__ import annotations

from pathlib import Path

from memory_yara.collect import COLUMNS

_STARTER_RULES = Path(__file__).parent / "rules" / "starter.yar"


def run_gui(paths: list[str] | None = None) -> int:
    from memory_yara.collect import scan_image
    from memory_yara.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(scan_image(str(p), str(_STARTER_RULES)).rows)
        return rows

    return run("memory_yara - scan a memory image (bundled starter "
              "rules)", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a memory image",
              open_is_dir=False, multi=True, alert_keys=("notable",))
