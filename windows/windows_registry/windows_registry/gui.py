"""Graphical hive browser (standard-library tkinter)."""

from __future__ import annotations

from windows_registry.hive import RegistryHive, to_text


def run(hive_path: str | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception:  # pragma: no cover
        print("error: tkinter is not available (Linux: 'apt install python3-tk').")
        return 2

    root = tk.Tk()
    root.title("windows_registry - hive browser")
    root.geometry("1150x680")
    state: dict = {"hive": None}

    bar = ttk.Frame(root, padding=6)
    bar.pack(fill="x")
    ttk.Button(bar, text="Open hive…", command=lambda: _open()).pack(side="left")
    status = ttk.Label(bar, text="no hive loaded")
    status.pack(side="left", padx=10)

    paned = ttk.Panedwindow(root, orient="horizontal")
    paned.pack(fill="both", expand=True)
    tree = ttk.Treeview(paned, show="tree")
    paned.add(tree, weight=2)
    cols = ("name", "type", "data")
    vtable = ttk.Treeview(paned, columns=cols, show="headings")
    for c, w in zip(cols, (220, 130, 560)):
        vtable.heading(c, text=c)
        vtable.column(c, width=w, anchor="w")
    paned.add(vtable, weight=3)

    node_key: dict[str, object] = {}

    def _open():
        p = filedialog.askopenfilename(title="Open a registry hive")
        if not p:
            return
        try:
            hive = RegistryHive(open(p, "rb").read())
        except Exception as e:  # noqa: BLE001
            status.config(text=f"failed: {e}")
            return
        state["hive"] = hive
        tree.delete(*tree.get_children())
        node_key.clear()
        rk = hive.root()
        rid = tree.insert("", "end", text=rk.name, open=True)
        node_key[rid] = rk
        _populate(rid, rk)
        status.config(text=f"{p}  -  root '{rk.name}', "
                           f"{'dirty' if hive.base.is_dirty else 'clean'}")

    def _populate(node_id, key):
        for child in tree.get_children(node_id):
            if tree.item(child, "text") == "…":
                tree.delete(child)
        for sub in key.subkeys():
            cid = tree.insert(node_id, "end", text=sub.name)
            node_key[cid] = sub
            if sub.node.subkey_count:
                tree.insert(cid, "end", text="…")

    def _on_open(_e):
        nid = tree.focus()
        key = node_key.get(nid)
        if key:
            _populate(nid, key)

    def _on_select(_e):
        key = node_key.get(tree.focus())
        vtable.delete(*vtable.get_children())
        if not key:
            return
        for v in key.values():
            vtable.insert("", "end", values=(v.name, v.type_name,
                                             to_text(v.data)[:600]))

    tree.bind("<<TreeviewOpen>>", _on_open)
    tree.bind("<<TreeviewSelect>>", _on_select)

    if hive_path:
        try:
            hive = RegistryHive(open(hive_path, "rb").read())
            state["hive"] = hive
            rk = hive.root()
            rid = tree.insert("", "end", text=rk.name, open=True)
            node_key[rid] = rk
            _populate(rid, rk)
            status.config(text=f"{hive_path}")
        except Exception as e:  # noqa: BLE001
            status.config(text=f"failed: {e}")

    root.mainloop()
    return 0
