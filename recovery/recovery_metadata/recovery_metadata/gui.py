"""Graphical $MFT entry list (see ``recovery_metadata gui``)."""
from __future__ import annotations
from pathlib import Path

from recovery_metadata.cli import _filter, _open
from recovery_metadata.guikit import run
from recovery_metadata.output import _COLUMNS, _row


def run_gui(image):
    def load(ps):
        rows = []
        for p in ps:
            vol = _open(Path(p), 0)
            for e in _filter(vol.iter_entries(include_unused=True)):
                rows.append(_row(vol, e))
        return rows
    return run("recovery_metadata — $MFT entries", load, columns=_COLUMNS,
               initial=[p for p in image if p] or None,
               open_label="Open $MFT / NTFS image", multi=False,
               alert_keys=("deleted",))
