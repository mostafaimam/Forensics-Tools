"""tkinter document viewer for utilities_ezview."""

from __future__ import annotations


def run_gui(paths: list[str] | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
    except Exception as e:  # noqa: BLE001
        print(f"GUI unavailable: {e}")
        return 2
    from utilities_ezview.extract import render

    root = tk.Tk()
    root.title("utilities_ezview")
    root.geometry("980x640")
    top = ttk.Frame(root); top.pack(fill="x", padx=6, pady=4)
    info = tk.StringVar()
    ttk.Label(top, textvariable=info).pack(side="left")
    txt = tk.Text(root, wrap="word", font=("Consolas", 10))
    txt.pack(fill="both", expand=True, padx=6, pady=4)

    def show(p):
        v = render(str(p))
        info.set(f"{p}   [{v.fmt}{(" / " + v.encoding) if v.encoding else ""}]"
                 + (f"   note: {v.note}" if v.note else ""))
        txt.delete("1.0", "end")
        txt.insert("1.0", v.text or v.error or "(no text)")

    def openf():
        f = filedialog.askopenfilename()
        if f:
            show(f)
    ttk.Button(top, text="Open", command=openf).pack(side="right")
    for p in (paths or []):
        if p:
            show(p); break
    root.mainloop()
    return 0
