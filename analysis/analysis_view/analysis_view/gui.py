"""tkinter reviewer (see ``analysis_view --gui``)."""

from __future__ import annotations

from pathlib import Path


def run_gui(paths: list[str] | None = None, *, review=None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, simpledialog, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    from analysis_view.filters import apply_search, apply_sort
    from analysis_view.htmlview import build_html
    from analysis_view.model import Review, Table
    from analysis_view.output import export_csv

    state: dict = {"table": None, "review": Review(), "review_path": None,
                   "sort": []}
    if review:
        state["review_path"] = str(review)
        state["review"] = Review.from_file(review)

    root = tk.Tk()
    root.title("analysis_view")
    root.geometry("1200x680")

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    path_var = tk.StringVar(value=";".join(paths) if paths else "")
    ttk.Entry(top, textvariable=path_var, width=42).pack(side="left")

    def browse():
        fs = filedialog.askopenfilenames(
            filetypes=[("tables", "*.csv *.tsv *.json *.jsonl *.xlsx"),
                       ("all", "*.*")])
        if fs:
            path_var.set(";".join(fs))
            do_load()

    ttk.Button(top, text="Open…", command=browse).pack(side="left", padx=3)
    ttk.Label(top, text=" search:").pack(side="left")
    q_var = tk.StringVar()
    ttk.Entry(top, textvariable=q_var, width=22).pack(side="left")
    hide_var = tk.BooleanVar()
    ttk.Checkbutton(top, text="hide reviewed", variable=hide_var,
                    command=lambda: repaint()).pack(side="left", padx=6)
    tag_var = tk.StringVar(value="")
    tag_box = ttk.Combobox(top, textvariable=tag_var, width=14,
                           state="readonly")
    tag_box.pack(side="left")
    status = ttk.Label(top, text="")
    status.pack(side="right")

    tree = ttk.Treeview(root, show="headings")
    vsb = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(root, orient="horizontal", command=tree.xview)
    tree.configure(yscroll=vsb.set, xscroll=hsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    hsb.pack(side="bottom", fill="x")
    tree.tag_configure("rev", background="#e9f2e9", foreground="#777")
    tree.tag_configure("tagged", background="#fff6df")

    def cols():
        return ["✓", "tags", "note"] + state["table"].display_columns()

    def do_load():
        raw = path_var.get().strip()
        if not raw:
            return
        try:
            state["table"] = Table.from_paths([p for p in raw.split(";") if p])
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("analysis_view", str(e))
            return
        c = cols()
        tree.config(columns=c)
        for name in c:
            tree.heading(name, text=name, command=lambda n=name: sort_by(n))
            tree.column(name, width=40 if name == "✓" else
                        (110 if name in ("tags", "note", "_source") else 150),
                        anchor="w")
        repaint()

    def current_rows():
        rows = list(state["table"].rows)
        rv = state["review"]
        rows = apply_search(rows, q_var.get())
        if hide_var.get():
            rows = [r for r in rows if r["_id"] not in rv.reviewed]
        tf = tag_var.get()
        if tf == "(untagged)":
            rows = [r for r in rows if not rv.tags.get(r["_id"])]
        elif tf:
            rows = [r for r in rows if tf in rv.tags.get(r["_id"], [])]
        for col, d in reversed(state["sort"]):
            rows = apply_sort(rows, f"{col}:{'desc' if d else 'asc'}")
        return rows

    def repaint(*_):
        if not state["table"]:
            return
        tree.delete(*tree.get_children())
        rv = state["review"]
        disp = state["table"].display_columns()
        rows = current_rows()
        for r in rows:
            rid = r["_id"]
            tags = rv.tags.get(rid, [])
            vals = ["✓" if rid in rv.reviewed else "",
                    ",".join(tags), rv.notes.get(rid, "")] + \
                   [r.get(c, "") for c in disp]
            tg = ()
            if rid in rv.reviewed:
                tg = ("rev",)
            elif tags:
                tg = ("tagged",)
            tree.insert("", "end", iid=rid, values=vals, tags=tg)
        tag_box["values"] = ["", "(untagged)"] + rv.all_tags()
        status.config(text=f"{len(rows)} / {len(state['table'].rows)} rows"
                      f"  ·  {len(rv.reviewed)} reviewed  ·  "
                      f"{len(rv.all_tags())} tags")

    def sort_by(col):
        s = state["sort"]
        for i, (c, d) in enumerate(s):
            if c == col:
                s[i] = (c, not d)
                break
        else:
            s.insert(0, (col, False))
        repaint()

    def _selected_ids():
        return list(tree.selection())

    def add_tag():
        ids = _selected_ids()
        if not ids:
            return
        t = simpledialog.askstring("Tag", "tag(s), comma-separated:")
        if not t:
            return
        new = [x.strip() for x in t.split(",") if x.strip()]
        for rid in ids:
            cur = set(state["review"].tags.get(rid, []))
            cur.update(new)
            state["review"].tags[rid] = sorted(cur)
        repaint()

    def clear_tags():
        for rid in _selected_ids():
            state["review"].tags.pop(rid, None)
        repaint()

    def toggle_reviewed():
        rv = state["review"]
        for rid in _selected_ids():
            if rid in rv.reviewed:
                rv.reviewed.discard(rid)
            else:
                rv.reviewed.add(rid)
        repaint()

    def edit_note(_evt=None):
        ids = _selected_ids()
        if not ids:
            return
        cur = state["review"].notes.get(ids[0], "")
        n = simpledialog.askstring("Note", "note:", initialvalue=cur)
        if n is not None:
            for rid in ids:
                if n:
                    state["review"].notes[rid] = n
                else:
                    state["review"].notes.pop(rid, None)
        repaint()

    def save_review():
        path = state["review_path"] or filedialog.asksaveasfilename(
            defaultextension=".json", initialfile="review.json")
        if not path:
            return
        state["review_path"] = path
        state["review"].save(path)
        status.config(text=f"review saved -> {path}")

    def export_csv_cmd():
        out = filedialog.asksaveasfilename(defaultextension=".csv")
        if not out:
            return
        export_csv(current_rows(), state["table"].display_columns(), out,
                   state["review"])
        status.config(text=f"exported -> {out}")

    def export_html_cmd():
        out = filedialog.asksaveasfilename(defaultextension=".html")
        if not out:
            return
        sub = Table(rows=current_rows(),
                    columns=state["table"].columns,
                    sources=state["table"].sources)
        Path(out).write_text(build_html(sub, state["review"],
                                        title=Path(out).stem), encoding="utf-8")
        status.config(text=f"HTML -> {out}")

    bar = ttk.Frame(root, padding=(6, 0, 6, 6))
    bar.pack(side="bottom", fill="x")
    for label, cmd in (("Tag", add_tag), ("Clear tags", clear_tags),
                       ("Reviewed", toggle_reviewed), ("Note", edit_note),
                       ("Save review", save_review),
                       ("Export CSV", export_csv_cmd),
                       ("Export HTML", export_html_cmd)):
        ttk.Button(bar, text=label, command=cmd).pack(side="left", padx=2)

    q_var.trace_add("write", repaint)
    tag_var.trace_add("write", repaint)
    tree.bind("<Double-1>", edit_note)
    root.bind("<r>", lambda e: toggle_reviewed())
    root.bind("<t>", lambda e: add_tag())

    if paths:
        root.after(60, do_load)
    root.mainloop()
    return 0
