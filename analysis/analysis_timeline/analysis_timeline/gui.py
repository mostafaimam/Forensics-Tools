"""Optional Tk desktop viewer.

Uses only the standard library ``tkinter``. On Linux the OS package
``python3-tk`` must be present; the CLI reports a clear message if it is not.
"""

from __future__ import annotations

import re
from pathlib import Path

from analysis_timeline.adapters import AdapterConfig, iter_events
from analysis_timeline.model import Event


def _load(inputs: list[str], cfg: AdapterConfig) -> tuple[list[Event], list[str]]:
    warnings: list[str] = []
    events: list[Event] = []
    for raw in inputs:
        p = Path(raw)
        paths = ([c for c in sorted(p.rglob("*"))
                  if c.is_file() and c.suffix.lower() in
                  (".csv", ".tsv", ".json", ".jsonl")]
                 if p.is_dir() else [p])
        for f in paths:
            if f.exists():
                events.extend(iter_events(f, cfg, warnings))
    events.sort(key=lambda e: (e.timestamp, e.timestamp_type, e.tool))
    return events, warnings


def run(inputs: list[str], cfg: AdapterConfig) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception:  # pragma: no cover - platform dependent
        print("error: tkinter is not available. Install it (Linux: "
              "'apt install python3-tk') or use --html for a browser viewer.")
        return 2

    events, warnings = _load(inputs, cfg) if inputs else ([], [])

    root = tk.Tk()
    root.title("analysis_timeline")
    root.geometry("1200x700")

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    ttk.Label(top, text="filter:").pack(side="left")
    q_var = tk.StringVar()
    ttk.Entry(top, textvariable=q_var, width=40).pack(side="left", padx=4)
    type_var = tk.StringVar(value="")
    tool_var = tk.StringVar(value="")
    type_box = ttk.Combobox(top, textvariable=type_var, width=16, state="readonly")
    tool_box = ttk.Combobox(top, textvariable=tool_var, width=16, state="readonly")
    type_box.pack(side="left", padx=4)
    tool_box.pack(side="left", padx=4)
    status = ttk.Label(top, text="")
    status.pack(side="right")

    cols = ("timestamp_utc", "timestamp_type", "tool", "host", "user",
            "description", "source_file")
    tree = ttk.Treeview(root, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=c, command=lambda cc=c: _sort(cc))
        tree.column(c, width=90 if c != "description" else 460, anchor="w")
    vsb = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")

    state = {"events": events, "sort": "timestamp_utc", "asc": True}

    def facets():
        type_box["values"] = [""] + sorted({e.timestamp_type for e in events})
        tool_box["values"] = [""] + sorted({e.tool for e in events})

    def current():
        q = q_var.get().strip()
        try:
            rx = re.compile(q, re.IGNORECASE) if q else None
        except re.error:
            rx = re.compile(re.escape(q), re.IGNORECASE) if q else None
        rows = []
        for e in state["events"]:
            if type_var.get() and e.timestamp_type != type_var.get():
                continue
            if tool_var.get() and e.tool != tool_var.get():
                continue
            if rx and not (rx.search(e.description) or rx.search(e.tool)
                           or rx.search(e.source_file)):
                continue
            rows.append(e)
        rows.sort(key=lambda e: getattr(e, _attr(state["sort"]), ""),
                  reverse=not state["asc"])
        return rows

    def _attr(col):
        return {"timestamp_utc": "timestamp"}.get(col, col)

    def refresh(*_):
        tree.delete(*tree.get_children())
        rows = current()
        for e in rows:
            r = e.as_row()
            tree.insert("", "end", values=tuple(r[c] for c in cols))
        status.config(text=f"{len(rows)} / {len(events)} events")

    def _sort(col):
        if state["sort"] == col:
            state["asc"] = not state["asc"]
        else:
            state["sort"], state["asc"] = col, True
        refresh()

    def open_files():
        picked = filedialog.askopenfilenames(
            title="Open timeline sources",
            filetypes=[("data", "*.csv *.tsv *.json *.jsonl"), ("all", "*.*")])
        if picked:
            new, _w = _load(list(picked), cfg)
            events.extend(new)
            events.sort(key=lambda e: (e.timestamp, e.timestamp_type, e.tool))
            state["events"] = events
            facets()
            refresh()

    ttk.Button(top, text="open…", command=open_files).pack(side="left", padx=4)
    for w in (q_var, type_var, tool_var):
        w.trace_add("write", refresh)

    facets()
    refresh()
    if warnings:
        status.config(text=status.cget("text") + f"  ({len(warnings)} warnings)")
    root.mainloop()
    return 0
