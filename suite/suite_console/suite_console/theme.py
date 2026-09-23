"""A dark, gold-accented ttk theme - restrained, not loud."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

BG = "#0f1117"
PANEL = "#171a24"
PANEL_ALT = "#1d2130"
BORDER = "#2a2d3a"
TEXT = "#e8e8f0"
TEXT_DIM = "#8b8ea3"
ACCENT = "#c9a24b"
ACCENT_HOVER = "#e0b95c"
ACCENT_TEXT = "#1a1408"
VIOLET = "#8b7cf6"
SUCCESS = "#4ade80"
ERROR = "#f87171"
WARN = "#fbbf24"

FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI Semibold", 17)
FONT_SUBTITLE = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 9)
FONT_SMALL = ("Segoe UI", 8)


def apply(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=BG)

    style.configure(".", background=BG, foreground=TEXT, font=FONT_UI,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    focuscolor=ACCENT)

    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("PanelAlt.TFrame", background=PANEL_ALT)

    style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_UI)
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("Dim.TLabel", background=BG, foreground=TEXT_DIM)
    style.configure("PanelDim.TLabel", background=PANEL, foreground=TEXT_DIM)
    style.configure("Title.TLabel", background=BG, foreground=TEXT,
                    font=FONT_TITLE)
    style.configure("Accent.TLabel", background=BG, foreground=ACCENT,
                    font=FONT_UI_BOLD)
    style.configure("Category.TLabel", background=PANEL, foreground=ACCENT,
                    font=FONT_UI_BOLD)

    style.configure("TEntry", fieldbackground=PANEL_ALT, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=BORDER, padding=6,
                    borderwidth=1, relief="flat")
    style.map("TEntry", bordercolor=[("focus", ACCENT)])

    style.configure("TCheckbutton", background=BG, foreground=TEXT)
    style.map("TCheckbutton", background=[("active", BG)])

    style.configure("TCombobox", fieldbackground=PANEL_ALT,
                    background=PANEL_ALT, foreground=TEXT,
                    arrowcolor=ACCENT, bordercolor=BORDER, padding=5)
    style.map("TCombobox",
             fieldbackground=[("readonly", PANEL_ALT)],
             foreground=[("readonly", TEXT)])
    root.option_add("*TCombobox*Listbox.background", PANEL_ALT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", ACCENT_TEXT)

    style.configure("TButton", background=PANEL_ALT, foreground=TEXT,
                    padding=(12, 7), borderwidth=0, font=FONT_UI_BOLD)
    style.map("TButton", background=[("active", BORDER),
                                     ("disabled", PANEL)])

    style.configure("Accent.TButton", background=ACCENT,
                    foreground=ACCENT_TEXT, padding=(16, 9),
                    borderwidth=0, font=FONT_UI_BOLD)
    style.map("Accent.TButton",
             background=[("active", ACCENT_HOVER), ("disabled", BORDER)],
             foreground=[("disabled", TEXT_DIM)])

    style.configure("Ghost.TButton", background=BG, foreground=TEXT_DIM,
                    padding=(8, 5), borderwidth=0, font=FONT_UI)
    style.map("Ghost.TButton", foreground=[("active", ACCENT)])

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, rowheight=26, borderwidth=0,
                    font=FONT_UI)
    style.configure("Treeview.Heading", background=PANEL_ALT,
                    foreground=ACCENT, font=FONT_UI_BOLD, relief="flat")
    style.map("Treeview", background=[("selected", ACCENT)],
             foreground=[("selected", ACCENT_TEXT)])
    style.map("Treeview.Heading", background=[("active", PANEL_ALT)])

    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                    padding=(16, 9), font=FONT_UI_BOLD, borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", PANEL_ALT)],
             foreground=[("selected", ACCENT)])

    style.configure("TPanedwindow", background=BG)
    style.configure("Sash", sashthickness=6, gripcount=0)

    style.configure("Vertical.TScrollbar", background=PANEL_ALT,
                    troughcolor=BG, arrowcolor=TEXT_DIM, bordercolor=BG,
                    width=12)
    style.configure("Horizontal.TScrollbar", background=PANEL_ALT,
                    troughcolor=BG, arrowcolor=TEXT_DIM, bordercolor=BG)

    style.configure("TSeparator", background=BORDER)
    style.configure("TLabelframe", background=BG, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=TEXT_DIM,
                    font=FONT_UI_BOLD)

    return style
