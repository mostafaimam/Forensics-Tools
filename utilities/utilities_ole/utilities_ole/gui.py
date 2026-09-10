"""Graphical viewer for utilities_ole."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    from utilities_ole.analyze import analyze
    from utilities_ole.guikit import run

    def load(ps):
        rows = []
        for p in ps:
            rep = analyze(str(p))
            for r in rep.rows():
                r["severity"] = rep.severity
                r["notable"] = ";".join(rep.notable)
                rows.append(r)
        return rows

    return run("utilities_ole - compound file metadata", load,
               columns=["kind", "name", "value", "detail", "severity",
                        "notable"],
               initial=[p for p in (paths or []) if p] or None,
               open_label="Open OLE2 / OOXML file", multi=True,
               alert_keys=("notable",))
