"""Graphical search over an analysis_index (see ``analysis_index gui``)."""

from __future__ import annotations

from pathlib import Path


def run_gui(index_dir: str | None = None, query: str | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    from analysis_index.query import QueryError, search
    from analysis_index.store import Index

    state: dict = {"index": None}
    root = tk.Tk()
    root.title("analysis_index — search")
    root.geometry("1100x650")

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    idx_var = tk.StringVar(value=index_dir or "")
    ttk.Entry(top, textvariable=idx_var, width=40).pack(side="left")

    def open_index(_evt=None):
        d = idx_var.get().strip()
        if not d:
            d = filedialog.askdirectory(title="index directory")
            idx_var.set(d or "")
        if not d:
            return
        try:
            state["index"] = Index(d)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("analysis_index", str(e))
            return
        s = state["index"].stats()
        status.config(text=f"{s['documents']} docs · {s['unique_terms']} terms")

    ttk.Button(top, text="Open index", command=open_index).pack(side="left",
                                                                padx=4)
    ttk.Label(top, text="   query:").pack(side="left")
    q_var = tk.StringVar()
    qe = ttk.Entry(top, textvariable=q_var)
    qe.pack(side="left", fill="x", expand=True, padx=4)

    cols = ("score", "matches", "kind", "size", "path")
    tree = ttk.Treeview(root, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=90 if c != "path" else 560, anchor="w")
    tree.pack(fill="both", expand=True, padx=6)
    snip = tk.Text(root, height=7, wrap="word")
    snip.pack(fill="x", padx=6, pady=6)
    status = ttk.Label(root, text="open an index, then type a query",
                       relief="sunken", anchor="w")
    status.pack(fill="x")

    results: list = []

    def do_search(_evt=None):
        if state["index"] is None:
            open_index()
        if state["index"] is None or not q_var.get().strip():
            return
        try:
            hits = search(state["index"], q_var.get(), limit=200)
        except QueryError as e:
            status.config(text=f"query error: {e}")
            return
        results[:] = hits
        tree.delete(*tree.get_children())
        for h in hits:
            tree.insert("", "end", values=(h.score, h.matches, h.kind, h.size,
                                           h.path))
        status.config(text=f"{len(hits)} matching document(s)")

    def show_snip(_evt=None):
        sel = tree.selection()
        if not sel:
            return
        i = tree.index(sel[0])
        snip.delete("1.0", "end")
        if i < len(results):
            snip.insert("end", "\n\n".join(results[i].snippets)
                        or "(no snippet)")

    qe.bind("<Return>", do_search)
    tree.bind("<<TreeviewSelect>>", show_snip)
    if index_dir:
        root.after(80, open_index)
    if query:
        def _preload():
            q_var.set(query)
            do_search()
        root.after(200, _preload)
    root.mainloop()
    return 0
