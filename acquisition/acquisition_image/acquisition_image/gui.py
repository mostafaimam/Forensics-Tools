"""tkinter acquisition wizard."""

from __future__ import annotations

import queue
import threading
from pathlib import Path


def run() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:  # noqa: BLE001
        print(f"tkinter unavailable: {e}")
        return 2

    from acquisition_image import devices as _devices
    from acquisition_image.imager import acquire, verify
    from acquisition_image.report import html_report, manifest, text_log

    root = tk.Tk()
    root.title("acquisition_image")
    root.geometry("720x620")
    pad = {"padx": 6, "pady": 3}

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    # source
    ttk.Label(frm, text="Source").grid(row=0, column=0, sticky="w", **pad)
    src_var = tk.StringVar()
    src_entry = ttk.Combobox(frm, textvariable=src_var, width=52)
    src_entry.grid(row=0, column=1, columnspan=2, sticky="we", **pad)
    try:
        src_entry["values"] = [f"{d['path']}  ({d['size_h']} {d.get('model','')})"
                               for d in _devices.list_disks()]
    except Exception:  # noqa: BLE001
        pass
    ttk.Button(frm, text="File…", command=lambda: src_var.set(
        filedialog.askopenfilename() or src_var.get())).grid(row=0, column=3, **pad)

    # output
    ttk.Label(frm, text="Output").grid(row=1, column=0, sticky="w", **pad)
    out_var = tk.StringVar()
    ttk.Entry(frm, textvariable=out_var, width=52).grid(
        row=1, column=1, columnspan=2, sticky="we", **pad)
    ttk.Button(frm, text="Save as…", command=lambda: out_var.set(
        filedialog.asksaveasfilename() or out_var.get())).grid(row=1, column=3, **pad)

    # format
    ttk.Label(frm, text="Format").grid(row=2, column=0, sticky="w", **pad)
    fmt_var = tk.StringVar(value="ewf")
    ttk.Combobox(frm, textvariable=fmt_var, width=12,
                 values=["raw", "split", "ewf"]).grid(row=2, column=1,
                                                      sticky="w", **pad)
    ttk.Label(frm, text="Split/segment size").grid(row=2, column=2, sticky="e",
                                                   **pad)
    split_var = tk.StringVar(value="2G")
    ttk.Entry(frm, textvariable=split_var, width=8).grid(row=2, column=3, **pad)

    verify_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(frm, text="verify after acquisition",
                    variable=verify_var).grid(row=3, column=1, sticky="w", **pad)

    meta_vars = {}
    for i, (key, label) in enumerate([("case_number", "Case #"),
                                      ("evidence_number", "Evidence #"),
                                      ("examiner", "Examiner"),
                                      ("description", "Description"),
                                      ("notes", "Notes")]):
        ttk.Label(frm, text=label).grid(row=4 + i, column=0, sticky="w", **pad)
        v = tk.StringVar()
        meta_vars[key] = v
        ttk.Entry(frm, textvariable=v, width=52).grid(
            row=4 + i, column=1, columnspan=3, sticky="we", **pad)

    bar = ttk.Progressbar(frm, length=680, mode="determinate")
    bar.grid(row=10, column=0, columnspan=4, sticky="we", **pad)
    log = tk.Text(frm, height=14, wrap="none")
    log.grid(row=11, column=0, columnspan=4, sticky="nsew", **pad)
    frm.rowconfigure(11, weight=1)
    frm.columnconfigure(1, weight=1)

    q: queue.Queue = queue.Queue()

    def _pump():
        try:
            while True:
                kind, payload = q.get_nowait()
                if kind == "progress":
                    done, total = payload
                    bar["maximum"] = total or 1
                    bar["value"] = done
                elif kind == "log":
                    log.insert("end", payload + "\n")
                    log.see("end")
                elif kind == "done":
                    start_btn.config(state="normal")
        except queue.Empty:
            pass
        root.after(150, _pump)

    def _worker():
        source = src_var.get().split("  (")[0].strip()
        out = out_var.get().strip()
        fmt = fmt_var.get()
        if not source or not out:
            q.put(("log", "! set a source and an output path"))
            q.put(("done", None))
            return
        meta = {k: v.get() for k, v in meta_vars.items()}
        try:
            from acquisition_image.cli import _size
            split = _size(split_var.get()) if split_var.get() else None
        except Exception:  # noqa: BLE001
            split = None
        cb = lambda d, t, e: q.put(("progress", (d, t)))  # noqa: E731
        try:
            res = acquire(source, out,
                          fmt="ewf" if fmt == "ewf" else "raw",
                          split_size=split if fmt == "split" else None,
                          segment_size=split if fmt == "ewf" else None,
                          metadata={**meta, "version": ""}, progress=cb)
            res.fmt = fmt
            q.put(("log", f"acquired {res.bytes_read} bytes  md5={res.hashes['md5']}"))
            if verify_var.get():
                q.put(("log", "verifying…"))
                v = verify(res.segments[0], fmt="ewf" if fmt == "ewf" else "raw",
                           expected=res.hashes, progress=cb)
                res.verify_hashes = {k: v[k] for k in ("md5", "sha1", "sha256")
                                     if k in v}
                res.verified = "ok" if v["match"] else "MISMATCH"
                q.put(("log", f"verification: {res.verified}"))
            base = Path(res.segments[0])
            base.with_suffix(base.suffix + ".txt").write_text(
                text_log(res, meta), encoding="utf-8")
            base.with_suffix(base.suffix + ".json").write_text(
                manifest(res, meta), encoding="utf-8")
            base.with_suffix(base.suffix + ".html").write_text(
                html_report(res, meta), encoding="utf-8")
            q.put(("log", f"wrote log / manifest / report beside {base.name}"))
        except Exception as e:  # noqa: BLE001
            q.put(("log", f"! {e}"))
        q.put(("done", None))

    def start():
        start_btn.config(state="disabled")
        log.delete("1.0", "end")
        threading.Thread(target=_worker, daemon=True).start()

    start_btn = ttk.Button(frm, text="Start acquisition", command=start)
    start_btn.grid(row=9, column=0, columnspan=4, **pad)

    _pump()
    root.mainloop()
    return 0
