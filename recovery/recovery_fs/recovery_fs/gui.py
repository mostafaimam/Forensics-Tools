"""Graphical viewer for recovery_fs."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from recovery_fs.guikit import run
    from recovery_fs.open import open_fs, FsError

    def load(ps):
        rows = []
        for p in ps:
            try:
                be, off, fs = open_fs(str(p))
            except FsError:
                continue
            for e in be.entries():
                rows.append(e.row())
            be.close()
        return rows

    return run("recovery_fs - file-system walker", load, columns=[
        "path", "type", "size", "allocated", "modified", "created",
        "inode", "fs"],
        initial=[p for p in (paths or []) if p] or None,
        open_label="Open image", multi=False, alert_keys=("allocated",))
