"""Graphical $MFT browser (standard-library tkinter)."""

from __future__ import annotations

from windows_mft.ntfs.attributes import iso_utc
from windows_mft.ntfs.mft import ROOT_ENTRY, open_mft


def run(source: str | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception:  # pragma: no cover - platform dependent
        print("error: tkinter is not available (Linux: 'apt install python3-tk').")
        return 2

    root = tk.Tk()
    root.title("windows_mft - $MFT browser")
    root.geometry("1150x680")

    state: dict = {"mft": None, "by_parent": {}, "by_entry": {}}

    bar = ttk.Frame(root, padding=6)
    bar.pack(fill="x")
    ttk.Button(bar, text="Open $MFT / image…", command=lambda: _open()).pack(side="left")
    status = ttk.Label(bar, text="no file loaded")
    status.pack(side="left", padx=10)
    only_stomp = tk.BooleanVar()
    ttk.Checkbutton(bar, text="timestomped only", variable=only_stomp,
                    command=lambda: _repopulate()).pack(side="right")

    paned = ttk.Panedwindow(root, orient="horizontal")
    paned.pack(fill="both", expand=True)

    tree = ttk.Treeview(paned, columns=("size", "state"), show="tree headings")
    tree.heading("#0", text="name")
    tree.heading("size", text="size")
    tree.heading("state", text="state")
    tree.column("size", width=110, anchor="e")
    tree.column("state", width=90, anchor="center")
    paned.add(tree, weight=3)

    detail = tk.Text(paned, wrap="none", width=60)
    paned.add(detail, weight=2)

    def _open():
        path = filedialog.askopenfilename(
            title="Open an extracted $MFT or an NTFS volume image")
        if not path:
            return
        try:
            mft = open_mft(path)
        except Exception as e:  # noqa: BLE001
            status.config(text=f"failed: {e}")
            return
        state["mft"] = mft
        by_parent: dict[int, list] = {}
        by_entry = {}
        stomp = 0
        for e in mft.iter_entries():
            by_entry[e.number] = e
            by_parent.setdefault(e.parent_entry, []).append(e)
            if e.timestomp.any:
                stomp += 1
        state["by_parent"] = by_parent
        state["by_entry"] = by_entry
        status.config(text=f"{path}  -  {len(by_entry)} entries, {stomp} timestomped")
        _repopulate()

    def _repopulate():
        tree.delete(*tree.get_children())
        if not state["mft"]:
            return
        _add_children("", ROOT_ENTRY)

    def _add_children(node, parent_entry):
        kids = sorted(state["by_parent"].get(parent_entry, []),
                      key=lambda e: (not e.is_directory, e.name.lower()))
        for e in kids:
            if e.number == parent_entry:
                continue
            if only_stomp.get() and not e.timestomp.any and not e.is_directory:
                continue
            label = e.name + ("  [deleted]" if e.deleted else "")
            iid = tree.insert(node, "end", text=label,
                              values=(e.logical_size,
                                      "dir" if e.is_directory else "file"),
                              tags=("stomp",) if e.timestomp.any else ())
            if e.is_directory and state["by_parent"].get(e.number):
                tree.insert(iid, "end", text="…")  # placeholder

    def _expand(event):
        iid = tree.focus()
        children = tree.get_children(iid)
        if len(children) == 1 and tree.item(children[0], "text") == "…":
            tree.delete(children[0])
            e = _entry_for(iid)
            if e:
                _add_children(iid, e.number)

    def _entry_for(iid):
        # match by label back to entry (name + position); simplest: walk siblings
        text = tree.item(iid, "text").replace("  [deleted]", "")
        parent = tree.parent(iid)
        pe = ROOT_ENTRY if not parent else (_entry_for(parent).number
                                            if _entry_for(parent) else ROOT_ENTRY)
        for e in state["by_parent"].get(pe, []):
            if e.name == text:
                return e
        return None

    def _select(event):
        e = _entry_for(tree.focus())
        detail.delete("1.0", "end")
        if not e:
            return
        mft = state["mft"]
        si, fn = e.si, e.fn
        lines = [
            f"entry {e.number}  seq {e.sequence}  "
            f"{'ALLOCATED' if e.in_use else 'DELETED'}",
            f"path : {mft.full_path(e)}",
            f"type : {'directory' if e.is_directory else 'file'}   "
            f"size : {e.logical_size}   hard links : {e.hard_links}",
            f"fixup ok : {e.fixup_ok}",
            "",
            "$STANDARD_INFORMATION",
            f"  created      {iso_utc(si.created) if si else ''}",
            f"  modified     {iso_utc(si.modified) if si else ''}",
            f"  mft modified {iso_utc(si.mft_modified) if si else ''}",
            f"  accessed     {iso_utc(si.accessed) if si else ''}",
            "",
            "$FILE_NAME (primary)",
            f"  created      {iso_utc(fn.created) if fn else ''}",
            f"  modified     {iso_utc(fn.modified) if fn else ''}",
            f"  mft modified {iso_utc(fn.mft_modified) if fn else ''}",
            f"  accessed     {iso_utc(fn.accessed) if fn else ''}",
            "",
            f"names ({len(e.all_names)}): "
            + ", ".join(f"{n.name}[ns{n.namespace}]" for n in e.all_names),
            "streams: " + ", ".join(
                f"{s.name or '<data>'}({s.size}{'R' if s.resident else 'N'})"
                for s in e.streams),
        ]
        if e.timestomp.any:
            lines += ["", "*** TIMESTAMP ANOMALIES ***"]
            lines += [f"  - {r}" for r in e.timestomp.reasons()]
        detail.insert("1.0", "\n".join(lines))

    tree.tag_configure("stomp", foreground="#b30000")
    tree.bind("<<TreeviewOpen>>", _expand)
    tree.bind("<<TreeviewSelect>>", _select)

    if source:
        root.after(50, lambda: (_load_path(source)))

    def _load_path(path):
        try:
            state["mft"] = open_mft(path)
        except Exception as e:  # noqa: BLE001
            status.config(text=f"failed: {e}")
            return
        by_parent, by_entry = {}, {}
        for ent in state["mft"].iter_entries():
            by_entry[ent.number] = ent
            by_parent.setdefault(ent.parent_entry, []).append(ent)
        state["by_parent"], state["by_entry"] = by_parent, by_entry
        status.config(text=f"{path}  -  {len(by_entry)} entries")
        _repopulate()

    root.mainloop()
    return 0
