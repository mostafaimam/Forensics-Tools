"""Graphical report builder (see ``analysis_report --gui``)."""
from __future__ import annotations

from pathlib import Path

from analysis_report.guikit import run
from analysis_report.ingest import load as load_source

COLUMNS = ["name", "tool", "kind", "rows", "alert_rows", "sha256", "path"]


def run_gui(paths: list[str] | None = None) -> int:
    def load(ps):
        rows = []
        for raw in ps:
            p = Path(raw)
            files = (sorted(f for f in p.rglob("*")
                            if f.suffix.lower() in (".csv", ".json", ".jsonl"))
                     if p.is_dir() else [p])
            for f in files:
                try:
                    s = load_source(str(f))
                except Exception:  # noqa: BLE001
                    continue
                rows.append({"name": s.name, "tool": s.tool, "kind": s.kind,
                             "rows": s.row_count, "alert_rows": s.alert_rows,
                             "sha256": s.sha256, "path": s.path})
        return rows

    return run("analysis_report — sources", load, columns=COLUMNS,
               initial=[p for p in (paths or []) if p] or None,
               open_label="Add CSV/JSON or folder", alert_keys=("alert_rows",))
