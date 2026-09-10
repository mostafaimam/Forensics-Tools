"""Shared tkinter results-table viewer for the Forensics Tools GUIs.

Vendored (copied) into each tool.  A tool provides a ``load`` callback that
turns a list of paths into ``list[dict]`` rows; this module gives a window
with an open bar, a filter box, a sortable table, a details pane and CSV /
JSON export.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def run(title: str, load, *, columns=None, initial=None, open_label="Open…",
        open_is_dir=False, alert_keys=("notable", "flags", "verdict", "status"),
        multi=True) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    state: dict = {"rows": [], "cols": list(columns) if columns else []}

    root = tk.Tk()
    root.title(title)
    root.geometry("1160x640")

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    path_var = tk.StringVar(value=";".join(initial) if initial else "")
    ttk.Entry(top, textvariable=path_var).pack(side="left", fill="x", expand=True)

    def browse():
        if open_is_dir:
            p = filedialog.askdirectory()
            paths = [p] if p else []
        elif multi:
            paths = list(filedialog.askopenfilenames())
        else:
            p = filedialog.askopenfilename()
            paths = [p] if p else []
        if paths:
            path_var.set(";".join(paths))
            do_load()

    ttk.Button(top, text="Browse", command=browse).pack(side="left", padx=4)
    ttk.Button(top, text=open_label, command=lambda: do_load()).pack(side="left")

    fbar = ttk.Frame(root, padding=(6, 0))
    fbar.pack(fill="x")
    ttk.Label(fbar, text="filter:").pack(side="left")
    q_var = tk.StringVar()
    ttk.Entry(fbar, textvariable=q_var).pack(side="left", fill="x", expand=True,
                                             padx=4)
    count = ttk.Label(fbar, text="")
    count.pack(side="right")

    mid = ttk.Panedwindow(root, orient="vertical")
    mid.pack(fill="both", expand=True, padx=6, pady=6)
    tframe = ttk.Frame(mid)
    tree = ttk.Treeview(tframe, show="headings")
    vsb = ttk.Scrollbar(tframe, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tframe, orient="horizontal", command=tree.xview)
    tree.configure(yscroll=vsb.set, xscroll=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    tframe.rowconfigure(0, weight=1)
    tframe.columnconfigure(0, weight=1)
    mid.add(tframe, weight=4)
    detail = tk.Text(mid, height=8, wrap="word")
    mid.add(detail, weight=1)
    tree.tag_configure("alert", background="#ffecec")

    status = ttk.Label(root, text="open a file", relief="sunken", anchor="w")
    status.pack(fill="x")

    sort_state: dict = {}

    def _alert(r: dict) -> bool:
        for k, v in r.items():
            if k.lower() in alert_keys:
                s = str(v).strip().lower()
                if s and s not in ("no", "false", "0", "clear", "unknown",
                                   "known-good", "n/a", ""):
                    return True
        return False

    def repaint():
        tree.delete(*tree.get_children())
        q = q_var.get().lower()
        cols = state["cols"]
        shown = 0
        for r in state["rows"]:
            vals = [str(r.get(c, "")) for c in cols]
            if q and q not in " ".join(vals).lower():
                continue
            tags = ("alert",) if _alert(r) else ()
            tree.insert("", "end", values=vals, tags=tags)
            shown += 1
        count.config(text=f"{shown} / {len(state['rows'])} rows")

    def set_columns(cols):
        state["cols"] = cols
        tree.config(columns=cols)
        for c in cols:
            tree.heading(c, text=c, command=lambda cc=c: sort_by(cc))
            tree.column(c, width=max(90, min(360, len(c) * 12)), anchor="w")

    def sort_by(col):
        asc = not sort_state.get(col, False)
        sort_state[col] = asc
        try:
            state["rows"].sort(key=lambda r: str(r.get(col, "")), reverse=not asc)
        except Exception:  # noqa: BLE001
            pass
        repaint()

    def do_load():
        raw = path_var.get().strip()
        if not raw:
            return
        paths = [p for p in raw.split(";") if p]
        status.config(text="loading…")
        root.update_idletasks()
        try:
            rows = list(load(paths))
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(title, str(e))
            status.config(text="load failed")
            return
        rows = [r for r in rows if isinstance(r, dict)]
        state["rows"] = rows
        cols = list(columns) if columns else (
            list(rows[0].keys()) if rows else [])
        set_columns(cols)
        repaint()
        alerts = sum(1 for r in rows if _alert(r))
        status.config(text=f"{len(rows)} row(s)"
                      + (f", {alerts} highlighted" if alerts else ""))

    def show_detail(_evt=None):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        detail.delete("1.0", "end")
        for c, v in zip(state["cols"], vals):
            detail.insert("end", f"{c}: {v}\n")

    def export(fmt):
        if not state["rows"]:
            return
        ext = ".csv" if fmt == "csv" else ".json"
        out = filedialog.asksaveasfilename(defaultextension=ext)
        if not out:
            return
        cols = state["cols"]
        if fmt == "csv":
            with open(out, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                w.writeheader()
                w.writerows(state["rows"])
        else:
            Path(out).write_text(json.dumps(state["rows"], indent=2,
                                            default=str), encoding="utf-8")
        status.config(text=f"exported {len(state['rows'])} rows -> {out}")

    q_var.trace_add("write", lambda *_: repaint())
    tree.bind("<<TreeviewSelect>>", show_detail)

    bbar = ttk.Frame(root, padding=(6, 0, 6, 6))
    bbar.pack(fill="x")
    ttk.Button(bbar, text="Export CSV", command=lambda: export("csv")).pack(
        side="left")
    ttk.Button(bbar, text="Export JSON", command=lambda: export("json")).pack(
        side="left", padx=4)

    if initial:
        root.after(80, do_load)
    root.mainloop()
    return 0
