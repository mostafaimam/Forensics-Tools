"""Graphical plist viewer (see ``macos_plist --gui``)."""
from __future__ import annotations

from macos_plist.flatten import flatten
from macos_plist.guikit import run
from macos_plist.reader import load_file
from macos_plist.nskeyedarchiver import unwrap


def run_gui(paths):
    def load(ps):
        rows = []
        for p in ps:
            lp = load_file(p)
            value = lp.value
            if getattr(lp, "is_keyed_archive", False):
                try:
                    value = unwrap(lp.value)
                except Exception:  # noqa: BLE001
                    pass
            for key, val in flatten(value).items():
                rows.append({"file": lp.source, "key": key,
                             "value": str(val)[:800]})
        return rows
    return run("macos_plist", load, columns=["file", "key", "value"],
               initial=[p for p in paths if p] or None,
               open_label="Open .plist file(s)")
