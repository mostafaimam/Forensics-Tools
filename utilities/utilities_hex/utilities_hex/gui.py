"""tkinter hex viewer + data-interpreter panel (also an embeddable widget)."""

from __future__ import annotations

from utilities_hex.hexview import file_size, hexdump, read_region
from utilities_hex.interp import interpret

_PAGE = 1024


def run_gui(paths: list[str] | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception as e:  # noqa: BLE001
        print(f"GUI unavailable: {e}")
        return 2

    state = {"path": None, "base": 0, "size": 0}

    root = tk.Tk()
    root.title("utilities_hex")
    root.geometry("1000x620")

    top = ttk.Frame(root)
    top.pack(fill="x", padx=6, pady=4)
    path_var = tk.StringVar()
    off_var = tk.StringVar(value="0")
    ttk.Entry(top, textvariable=path_var).pack(side="left", fill="x",
                                               expand=True)

    body = ttk.Frame(root)
    body.pack(fill="both", expand=True, padx=6, pady=4)
    txt = tk.Text(body, font=("Courier New", 10), wrap="none", width=76)
    txt.pack(side="left", fill="both", expand=True)
    panel = ttk.Treeview(body, columns=("v",), show="tree headings",
                         height=30)
    panel.heading("#0", text="type")
    panel.heading("v", text="value")
    panel.column("#0", width=130)
    panel.column("v", width=240)
    panel.pack(side="right", fill="y")

    def load(p):
        state["path"] = p
        state["size"] = file_size(p) or 0
        state["base"] = 0
        path_var.set(p)
        render()

    def render():
        p = state["path"]
        if not p:
            return
        data = read_region(p, state["base"], _PAGE)
        txt.delete("1.0", "end")
        txt.insert("1.0", hexdump(data, base=state["base"]))
        interpret_offset()

    def interpret_offset():
        p = state["path"]
        if not p:
            return
        try:
            off = int(off_var.get(), 0)
        except ValueError:
            return
        buf = read_region(p, off, 32)
        info = interpret(buf, 0)
        ts = info.pop("timestamps", {})
        panel.delete(*panel.get_children())
        for k, v in info.items():
            if k in ("offset", "offset_hex"):
                continue
            panel.insert("", "end", text=k, values=(v,))
        for k, v in ts.items():
            panel.insert("", "end", text=f"ts:{k}", values=(v,))

    def page(delta):
        state["base"] = max(0, min(state["size"],
                                   state["base"] + delta * _PAGE))
        render()

    def open_file():
        f = filedialog.askopenfilename()
        if f:
            load(f)

    ttk.Button(top, text="Open", command=open_file).pack(side="left", padx=3)
    ttk.Label(top, text="interpret @").pack(side="left", padx=(12, 2))
    e = ttk.Entry(top, textvariable=off_var, width=12)
    e.pack(side="left")
    e.bind("<Return>", lambda _e: interpret_offset())
    ttk.Button(top, text="◀", command=lambda: page(-1)).pack(side="left",
                                                             padx=(12, 2))
    ttk.Button(top, text="▶", command=lambda: page(1)).pack(side="left")

    for p in (paths or []):
        if p:
            load(p)
            break

    root.mainloop()
    return 0
