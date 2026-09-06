"""Graphical .lnk viewer (standard-library tkinter)."""

from __future__ import annotations

from pathlib import Path

from windows_lnk.cli import _row
from windows_lnk.lnk import LnkError, parse


def run(paths: list[str]) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception:  # pragma: no cover
        print("error: tkinter is not available (Linux: 'apt install python3-tk').")
        return 2

    root = tk.Tk()
    root.title("windows_lnk")
    root.geometry("1150x650")
    rows: list[tuple] = []

    bar = ttk.Frame(root, padding=6)
    bar.pack(fill="x")
    ttk.Button(bar, text="Open .lnk / folder…",
               command=lambda: _open()).pack(side="left")
    status = ttk.Label(bar, text="")
    status.pack(side="left", padx=10)

    paned = ttk.Panedwindow(root, orient="horizontal")
    paned.pack(fill="both", expand=True)
    lst = ttk.Treeview(paned, columns=("target",), show="tree headings")
    lst.heading("#0", text="file")
    lst.heading("target", text="target")
    lst.column("target", width=500)
    paned.add(lst, weight=2)
    detail = tk.Text(paned, wrap="none")
    paned.add(detail, weight=3)

    def _load(files):
        for f in files:
            try:
                lnk = parse(Path(f).read_bytes(), str(f))
            except (LnkError, OSError) as e:
                rows.append((Path(f).name, f"<error: {e}>", None))
                continue
            rows.append((Path(f).name, lnk.target_path, lnk))
        _refresh()

    def _open():
        p = filedialog.askopenfilenames(filetypes=[("Shell links", "*.lnk")])
        if not p and filedialog:
            d = filedialog.askdirectory()
            if d:
                p = [str(x) for x in sorted(Path(d).rglob("*.lnk"))]
        if p:
            _load(list(p))

    def _refresh():
        lst.delete(*lst.get_children())
        for i, (name, target, _lnk) in enumerate(rows):
            lst.insert("", "end", iid=str(i), text=name, values=(target,))
        status.config(text=f"{len(rows)} file(s)")

    def _select(_e):
        try:
            _n, _t, lnk = rows[int(lst.focus())]
        except (ValueError, IndexError):
            return
        detail.delete("1.0", "end")
        if lnk is None:
            return
        r = _row(lnk, lnk.source)
        for k, v in r.items():
            if v:
                detail.insert("end", f"{k:<26} {v}\n")
        if lnk.target_items:
            detail.insert("end", "\nshell items:\n")
            for it in lnk.target_items:
                detail.insert("end", f"  {it}\n")

    lst.bind("<<TreeviewSelect>>", _select)
    if paths:
        files = []
        for p in paths:
            pp = Path(p)
            files.extend(str(x) for x in pp.rglob("*.lnk")) if pp.is_dir() \
                else files.append(str(pp))
        _load(files)
    root.mainloop()
    return 0
