"""Minimal tkinter image browser: open, inspect, export partitions, serve NBD."""

from __future__ import annotations

import threading
from pathlib import Path

from mounting_image.formats import ImageError, SliceImage, open_image
from mounting_image.partitions import detect
from mounting_image.report import _si


def run(path: str | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    state: dict = {"img": None, "parts": [], "scheme": "none", "server": None}

    root = tk.Tk()
    root.title("mounting_image")
    root.geometry("880x520")

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    path_var = tk.StringVar(value=path or "")
    ttk.Entry(top, textvariable=path_var).pack(side="left", fill="x", expand=True)

    info = tk.Text(root, height=6, wrap="none")
    info.pack(fill="x", padx=8)

    cols = ("#", "type", "start (bytes)", "start LBA", "size", "name")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=12)
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=130, anchor="w")
    tree.pack(fill="both", expand=True, padx=8, pady=8)

    status = ttk.Label(root, text="open an image", relief="sunken", anchor="w")
    status.pack(fill="x")

    def load(_evt=None):
        p = path_var.get().strip()
        if not p:
            return
        try:
            img = open_image(p)
            scheme, parts = detect(img)
        except (ImageError, OSError) as e:
            messagebox.showerror("mounting_image", str(e))
            return
        state.update(img=img, parts=parts, scheme=scheme)
        info.delete("1.0", "end")
        sub = f" / {img.subtype}" if getattr(img, "subtype", "") else ""
        info.insert("end", f"format: {img.format_name}{sub}\n"
                           f"size:   {img.size} bytes ({_si(img.size)})\n"
                           f"scheme: {scheme}\n")
        for k, v in (getattr(img, "metadata", {}) or {}).items():
            info.insert("end", f"{k}: {v}\n")
        tree.delete(*tree.get_children())
        for pt in parts:
            tree.insert("", "end", values=(pt.index, pt.type_label,
                        pt.start_offset, pt.start_lba, _si(pt.length), pt.name))
        status.config(text=f"{len(parts)} partition(s)")

    def _selected_target():
        img = state["img"]
        if img is None:
            return None
        sel = tree.selection()
        if not sel:
            return img
        idx = int(tree.item(sel[0], "values")[0])
        for pt in state["parts"]:
            if pt.index == idx:
                return SliceImage(img, pt.start_offset, pt.length)
        return img

    def export():
        tgt = _selected_target()
        if tgt is None:
            return
        out = filedialog.asksaveasfilename(defaultextension=".raw")
        if not out:
            return

        def work():
            n = 0
            with open(out, "wb") as fh:
                for chunk in tgt.stream():
                    fh.write(chunk)
                    n += len(chunk)
            status.config(text=f"exported {n} bytes -> {out}")
        threading.Thread(target=work, daemon=True).start()
        status.config(text="exporting...")

    def serve():
        from mounting_image.nbd import NBDServer
        tgt = _selected_target()
        if tgt is None:
            return
        if state["server"]:
            state["server"].shutdown()
            state["server"] = None
            status.config(text="NBD server stopped")
            return
        srv = NBDServer(tgt, "127.0.0.1", 10809, "image")
        srv.serve_in_thread()
        state["server"] = srv
        status.config(text="NBD export on 127.0.0.1:10809 (click again to stop)")

    def copy_offset():
        sel = tree.selection()
        if sel:
            root.clipboard_clear()
            root.clipboard_append(str(tree.item(sel[0], "values")[2]))
            status.config(text="start offset copied")

    ttk.Button(top, text="Browse", command=lambda: path_var.set(
        filedialog.askopenfilename() or path_var.get())).pack(side="left", padx=4)
    ttk.Button(top, text="Open", command=load).pack(side="left")

    bar = ttk.Frame(root, padding=(8, 0, 8, 8))
    bar.pack(fill="x")
    ttk.Button(bar, text="Export selected → raw", command=export).pack(
        side="left")
    ttk.Button(bar, text="Copy start offset", command=copy_offset).pack(
        side="left", padx=4)
    ttk.Button(bar, text="Toggle NBD server", command=serve).pack(side="left")

    if path:
        root.after(100, load)
    root.mainloop()
    if state["img"]:
        state["img"].close()
    return 0
