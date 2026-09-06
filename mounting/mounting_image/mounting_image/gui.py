"""tkinter image browser: open, inspect, export, serve NBD, mount as a drive."""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from mounting_image import osmount
from mounting_image.formats import ImageError, SliceImage, open_image, sniff
from mounting_image.partitions import detect
from mounting_image.report import _si
from mounting_image.vhdwrite import write_fixed_vhd


def run(path: str | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    state: dict = {"img": None, "parts": [], "scheme": "none", "server": None,
                   "drive": None}
    backend = osmount.current_backend()

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

    # -- mount as a read-only drive --------------------------------
    def mount_drive():
        if state["drive"]:
            _unmount_drive()
            return
        img = state["img"]
        if img is None:
            return
        src = path_var.get().split("  (")[0].strip()
        fmt = "vhd" if backend == "windows" else "raw"
        part = None
        sel = tree.selection()
        if sel:
            part = int(tree.item(sel[0], "values")[0])
        letter = letter_var.get().rstrip(":") or None
        mnt = None
        if backend != "windows":
            mnt = filedialog.askdirectory(title="Mount point (empty directory)")
            if not mnt:
                return
        mount_btn.config(state="disabled")
        status.config(text="materialising image…")

        def work():
            temp = True
            try:
                if sniff(src) == fmt:
                    matimg, temp = src, False
                else:
                    d = tempfile.mkdtemp(prefix="mounting_image_")
                    matimg = str(Path(d) / (Path(src).stem + "." + fmt))
                    whole = open_image(src)
                    if fmt == "vhd":
                        write_fixed_vhd(whole, matimg)
                    else:
                        with open(matimg, "wb") as fh:
                            for c in whole.stream():
                                fh.write(c)
                    whole.close()
                if backend == "windows":
                    res = osmount.mount_windows(matimg, letter, part, temp)
                elif backend == "macos":
                    res = osmount.mount_macos(matimg, temp)
                else:
                    res = osmount.mount_linux(matimg, mnt, fstype=None,
                                              partition=part or 1, temp=temp)
                mid = osmount.register(res, src, mnt)
                state["drive"] = {"id": mid, **res.__dict__, "mountpoint": mnt}
                vols = ", ".join(v["name"] for v in res.volumes)
                status.config(text=f"mounted read-only: {vols}  "
                                   f"(click 'Unmount drive' to detach)")
                mount_btn.config(text="Unmount drive", state="normal")
            except (osmount.OsMountError, OSError, ImageError) as e:
                messagebox.showerror("mount", str(e))
                status.config(text="mount failed")
                mount_btn.config(state="normal")
        threading.Thread(target=work, daemon=True).start()

    def _unmount_drive():
        d = state["drive"]
        if not d:
            return
        try:
            osmount.unmount(d)
            osmount.deregister(d["id"])
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("unmount", str(e))
            return
        state["drive"] = None
        mount_btn.config(text="Mount as read-only drive")
        status.config(text="drive detached")

    bar = ttk.Frame(root, padding=(8, 0, 8, 8))
    bar.pack(fill="x")
    ttk.Button(bar, text="Export selected → raw", command=export).pack(
        side="left")
    ttk.Button(bar, text="Copy start offset", command=copy_offset).pack(
        side="left", padx=4)
    ttk.Button(bar, text="Toggle NBD server", command=serve).pack(side="left")

    mbar = ttk.Frame(root, padding=(8, 0, 8, 8))
    mbar.pack(fill="x")
    mount_btn = ttk.Button(mbar, text="Mount as read-only drive",
                           command=mount_drive)
    mount_btn.pack(side="left")
    letter_var = tk.StringVar()
    if backend == "windows":
        ttk.Label(mbar, text="  drive letter:").pack(side="left")
        try:
            free = osmount.free_drive_letters()
        except Exception:  # noqa: BLE001
            free = list("XYZ")
        cb = ttk.Combobox(mbar, textvariable=letter_var, width=4,
                          values=free, state="readonly")
        if free:
            cb.current(0)
        cb.pack(side="left")
        ttk.Label(mbar, text="  (converts to a temp VHD, mounts it "
                             "read-only via Windows)").pack(side="left")
    else:
        ttk.Label(mbar, text=f"  ({backend}: you'll pick a mount point)"
                  ).pack(side="left")

    if path:
        root.after(100, load)
    root.mainloop()
    if state["drive"]:
        _unmount_drive()
    if state["img"]:
        state["img"].close()
    return 0
