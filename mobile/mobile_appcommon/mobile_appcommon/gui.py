"""Graphical viewer for mobile_appcommon."""

from __future__ import annotations

from mobile_appcommon.collect import COLUMNS


def run_gui(paths: list[str] | None = None) -> int:
    from mobile_appcommon.collect import decode_file
    from mobile_appcommon.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rows.extend(decode_file(str(p)).rows)
        return rows

    return run("mobile_appcommon - plist / protobuf blob inspector", load,
              columns=COLUMNS,
              initial=[p for p in (paths or []) if p] or None,
              open_label="Open a blob file",
              open_is_dir=False, multi=True)
