"""Graphical transaction-log inspector (see ``windows_reglog --gui``)."""
from __future__ import annotations

from windows_reglog.guikit import run
from windows_reglog.logfile import parse_log

COLUMNS = ["log", "sequence", "entry_size", "dirty_pages", "bytes",
           "hash1_ok", "hash2_ok"]


def run_gui(paths: list[str]) -> int:
    def load(ps):
        rows = []
        for p in ps:
            base, entries = parse_log(open(p, "rb").read())
            for e in entries:
                rows.append({
                    "log": p.rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
                    "sequence": e.sequence, "entry_size": e.entry_size,
                    "dirty_pages": len(e.pages),
                    "bytes": sum(pg.size for pg in e.pages),
                    "hash1_ok": "yes" if e.hash1_ok else "NO",
                    "hash2_ok": "yes" if e.hash2_ok else "NO"})
        return rows

    return run("windows_reglog — .LOG1 / .LOG2 entries", load, columns=COLUMNS,
               initial=[p for p in paths if p] or None,
               open_label="Open .LOG1 / .LOG2")
