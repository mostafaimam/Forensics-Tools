"""The main console window."""

from __future__ import annotations

import csv
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from suite_console import theme
from suite_console.discovery import ToolInfo, discover_tools, find_repo_root
from suite_console.introspect import (CommandSpec, FieldSpec, FormSpec,
                                      IntrospectError, build_form)
from suite_console.runner import RunHandle, launch_native_gui, run

_CATEGORY_ICONS = {
    "acquisition": "\N{INBOX TRAY}", "analysis": "\N{BAR CHART}",
    "apps": "\N{SPEECH BALLOON}", "browser": "\N{GLOBE WITH MERIDIANS}",
    "cloud": "\N{CLOUD}", "linux": "\N{PENGUIN}", "macos": "\N{GREEN APPLE}",
    "memory": "\N{BRAIN}", "mobile": "\N{MOBILE PHONE}",
    "mounting": "\N{OPEN LOCK}", "network": "\N{SATELLITE ANTENNA}",
    "recovery": "\N{LEFT-POINTING MAGNIFYING GLASS}",
    "utilities": "\N{WRENCH}", "windows": "\N{DESKTOP COMPUTER}",
}
_DIR_DIALOG_KINDS = {"dir"}
_OUT_DIALOG_KINDS = {"outpath"}


class ConsoleApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Forensics Tools Console")
        self.root.geometry("1440x920")
        self.root.minsize(1100, 700)
        self.style = theme.apply(root)

        self.repo_root = find_repo_root()
        self.tools: list[ToolInfo] = discover_tools(self.repo_root)
        self.tools_by_name = {t.name: t for t in self.tools}

        self.current_tool: ToolInfo | None = None
        self.current_form: FormSpec | None = None
        self.current_command: CommandSpec | None = None
        self.field_widgets: dict[str, tuple[FieldSpec, object]] = {}
        self.run_handle: RunHandle | None = None
        self.last_output_path: Path | None = None

        self._build_layout()
        self._populate_tree()
        self._show_welcome()

    # -- layout ----------------------------------------------------
    def _build_layout(self) -> None:
        self._build_topbar()

        body = ttk.PanedWindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True)

        sidebar = ttk.Frame(body, style="Panel.TFrame", width=320)
        body.add(sidebar, weight=0)
        self._build_sidebar(sidebar)

        main = ttk.PanedWindow(body, orient="vertical")
        body.add(main, weight=1)

        top_main = ttk.Frame(main)
        main.add(top_main, weight=3)
        self._build_tool_pane(top_main)

        bottom_main = ttk.Frame(main)
        main.add(bottom_main, weight=2)
        self._build_output_pane(bottom_main)

        self._build_statusbar()

    def _build_topbar(self) -> None:
        bar = ttk.Frame(self.root, style="Panel.TFrame", padding=(18, 12))
        bar.pack(fill="x", side="top")

        ttk.Label(bar, text="\N{ELECTRIC TORCH} Forensics Tools Console",
                 style="Title.TLabel", background=theme.PANEL).pack(
            side="left")
        ttk.Label(bar, text=f"  {len(discover_tools())} tools, one shell",
                 style="PanelDim.TLabel").pack(side="left", padx=(8, 0))

        case_frame = ttk.Frame(bar, style="Panel.TFrame")
        case_frame.pack(side="right")
        self.case_vars: dict[str, tk.StringVar] = {}
        for label, dest in (("Case ID", "case_id"),
                            ("Examiner", "examiner"),
                            ("Evidence ID", "evidence_id")):
            ttk.Label(case_frame, text=label, style="PanelDim.TLabel").pack(
                side="left", padx=(10, 4))
            var = tk.StringVar()
            ttk.Entry(case_frame, textvariable=var, width=14).pack(
                side="left")
            self.case_vars[dest] = var

    def _build_sidebar(self, parent: ttk.Frame) -> None:
        pad = ttk.Frame(parent, style="Panel.TFrame", padding=(14, 14))
        pad.pack(fill="both", expand=True)

        ttk.Label(pad, text="SEARCH", style="PanelDim.TLabel",
                 font=theme.FONT_SMALL).pack(anchor="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._populate_tree())
        entry = ttk.Entry(pad, textvariable=self.search_var)
        entry.pack(fill="x", pady=(2, 10))

        self.tree = ttk.Treeview(pad, show="tree", selectmode="browse")
        self.tree.pack(fill="both", expand=True)
        vs = ttk.Scrollbar(pad, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _build_tool_pane(self, parent: ttk.Frame) -> None:
        outer = ttk.Frame(parent, padding=(20, 16))
        outer.pack(fill="both", expand=True)
        self.tool_pane = outer

        header = ttk.Frame(outer)
        header.pack(fill="x")
        self.tool_title = ttk.Label(header, text="", style="Title.TLabel")
        self.tool_title.pack(side="left")
        self.native_gui_btn = ttk.Button(
            header, text="\N{FRAME WITH PICTURE} Open native GUI",
            command=self._on_open_native_gui, style="Ghost.TButton")
        self.run_btn = ttk.Button(header, text="\N{BLACK RIGHT-POINTING TRIANGLE} Run",
                                  command=self._on_run, style="Accent.TButton")
        self.cancel_btn = ttk.Button(header, text="Cancel",
                                     command=self._on_cancel)

        self.tool_desc = ttk.Label(outer, text="", style="Dim.TLabel",
                                   wraplength=900, justify="left")
        self.tool_desc.pack(fill="x", pady=(4, 12), anchor="w")

        cmd_row = ttk.Frame(outer)
        cmd_row.pack(fill="x", pady=(0, 8))
        self.cmd_label = ttk.Label(cmd_row, text="Command:")
        self.cmd_var = tk.StringVar()
        self.cmd_combo = ttk.Combobox(cmd_row, textvariable=self.cmd_var,
                                      state="readonly", width=20)
        self.cmd_combo.bind("<<ComboboxSelected>>", self._on_command_change)

        canvas = tk.Canvas(outer, bg=theme.BG, highlightthickness=0)
        form_scroll = ttk.Scrollbar(outer, orient="vertical",
                                    command=canvas.yview)
        self.form_frame = ttk.Frame(canvas)
        self.form_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.form_frame, anchor="nw")
        canvas.configure(yscrollcommand=form_scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        form_scroll.pack(side="right", fill="y")
        self._form_canvas = canvas

    def _build_output_pane(self, parent: ttk.Frame) -> None:
        outer = ttk.Frame(parent, padding=(20, 0, 20, 16))
        outer.pack(fill="both", expand=True)

        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True)
        self.output_nb = nb

        console_frame = ttk.Frame(nb)
        nb.add(console_frame, text="Console")
        self.console_text = tk.Text(
            console_frame, bg=theme.PANEL, fg=theme.TEXT,
            insertbackground=theme.TEXT, font=theme.FONT_MONO,
            relief="flat", padx=10, pady=8, wrap="word")
        self.console_text.pack(fill="both", expand=True, side="left")
        cs = ttk.Scrollbar(console_frame, orient="vertical",
                           command=self.console_text.yview)
        cs.pack(side="right", fill="y")
        self.console_text.configure(yscrollcommand=cs.set, state="disabled")
        self.console_text.tag_configure("err", foreground=theme.ERROR)
        self.console_text.tag_configure("ok", foreground=theme.SUCCESS)

        results_frame = ttk.Frame(nb)
        nb.add(results_frame, text="Results")
        self.results_tree = ttk.Treeview(results_frame, show="headings")
        self.results_tree.pack(fill="both", expand=True, side="left")
        rs = ttk.Scrollbar(results_frame, orient="vertical",
                           command=self.results_tree.yview)
        rs.pack(side="right", fill="y")
        self.results_tree.configure(yscrollcommand=rs.set)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 6))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var,
                 style="PanelDim.TLabel").pack(side="left")

    # -- sidebar population ------------------------------------------
    def _populate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower()
        by_category: dict[str, list[ToolInfo]] = {}
        for t in self.tools:
            if query and query not in t.name.lower() and \
                    query not in t.description.lower() and \
                    not any(query in k.lower() for k in t.keywords):
                continue
            by_category.setdefault(t.category, []).append(t)

        for category in sorted(by_category):
            icon = _CATEGORY_ICONS.get(category, "\N{BLACK SQUARE}")
            node = self.tree.insert(
                "", "end", iid=f"cat:{category}",
                text=f"{icon}  {category}  ({len(by_category[category])})",
                open=bool(query))
            for t in sorted(by_category[category], key=lambda x: x.name):
                self.tree.insert(node, "end", iid=f"tool:{t.name}",
                                 text=f"    {t.name}")

    def _on_tree_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("tool:"):
            return
        name = sel[0].split(":", 1)[1]
        self._select_tool(self.tools_by_name[name])

    # -- tool selection -----------------------------------------------
    def _show_welcome(self) -> None:
        self.tool_title.configure(
            text=f"Welcome \N{WAVING HAND SIGN}")
        self.tool_desc.configure(
            text=f"{len(self.tools)} tools across "
            f"{len({t.category for t in self.tools})} categories, all "
            f"discovered automatically from {self.repo_root}. Pick one "
            f"from the left to configure and run it.")
        self.native_gui_btn.pack_forget()
        self.run_btn.pack_forget()
        self.cancel_btn.pack_forget()
        self.cmd_label.pack_forget()
        self.cmd_combo.pack_forget()

    def _select_tool(self, tool: ToolInfo) -> None:
        self.current_tool = tool
        self.tool_title.configure(text=tool.name)
        self.tool_desc.configure(text=tool.description or "(no "
                                 "description available)")
        self.run_btn.pack(side="right")
        self.cancel_btn.pack_forget()
        if tool.has_gui:
            self.native_gui_btn.pack(side="right", padx=(0, 10))
        else:
            self.native_gui_btn.pack_forget()

        try:
            self.current_form = build_form(tool)
        except IntrospectError as e:
            self.current_form = None
            self._clear_form()
            ttk.Label(self.form_frame, text=str(e),
                     style="Dim.TLabel").pack(anchor="w", pady=20)
            self.status_var.set(f"Could not load {tool.name}")
            return

        if self.current_form.has_subcommands:
            names = [c.name for c in self.current_form.commands]
            self.cmd_combo.configure(values=names)
            self.cmd_var.set(names[0])
            self.cmd_label.pack(side="left", padx=(0, 6))
            self.cmd_combo.pack(side="left")
            self.current_command = self.current_form.commands[0]
        else:
            self.cmd_label.pack_forget()
            self.cmd_combo.pack_forget()
            self.current_command = self.current_form.commands[0]

        self._render_form()
        self.status_var.set(f"{tool.name} ready — {tool.category}")

    def _on_command_change(self, _event=None) -> None:
        name = self.cmd_var.get()
        self.current_command = next(
            c for c in self.current_form.commands if c.name == name)
        self._render_form()

    # -- form rendering -----------------------------------------------
    def _clear_form(self) -> None:
        for child in self.form_frame.winfo_children():
            child.destroy()
        self.field_widgets.clear()

    def _render_form(self) -> None:
        self._clear_form()
        if self.current_command is None:
            return
        if not self.current_command.fields:
            ttk.Label(self.form_frame, text="No parameters — just press "
                     "Run.", style="Dim.TLabel").pack(anchor="w", pady=16)
            return

        for field in self.current_command.fields:
            row = ttk.Frame(self.form_frame)
            row.pack(fill="x", pady=6)
            star = " *" if field.required else ""
            ttk.Label(row, text=field.label + star, width=22,
                     anchor="w").pack(side="left")

            if field.kind == "flag":
                var = tk.BooleanVar(value=bool(field.default))
                ttk.Checkbutton(row, variable=var).pack(side="left")
                widget = var
            elif field.kind == "choice":
                var = tk.StringVar(
                    value=str(field.default) if field.default else "")
                ttk.Combobox(row, textvariable=var, values=field.choices,
                            state="readonly", width=24).pack(
                    side="left", fill="x", expand=True)
                widget = var
            elif field.kind in ("path", "outpath", "dir"):
                var = tk.StringVar()
                ttk.Entry(row, textvariable=var).pack(
                    side="left", fill="x", expand=True)
                ttk.Button(row, text="Browse…", style="Ghost.TButton",
                          command=lambda f=field, v=var:
                          self._browse(f, v)).pack(side="left", padx=(6, 0))
                widget = var
            else:
                var = tk.StringVar(
                    value="" if field.default in (None, "") else
                    str(field.default))
                ttk.Entry(row, textvariable=var).pack(
                    side="left", fill="x", expand=True)
                widget = var

            if field.help:
                ttk.Label(self.form_frame, text=field.help,
                         style="Dim.TLabel",
                         font=theme.FONT_SMALL).pack(anchor="w",
                                                     padx=(226, 0))
            self.field_widgets[field.dest] = (field, widget)

    def _browse(self, field: FieldSpec, var: tk.StringVar) -> None:
        if field.kind == "dir":
            path = filedialog.askdirectory(title=f"Choose {field.label}")
        elif field.kind == "outpath":
            path = filedialog.asksaveasfilename(title=f"Save {field.label}")
        else:
            path = filedialog.askopenfilename(title=f"Choose {field.label}")
        if path:
            var.set(path)

    # -- assembling & running -------------------------------------------
    def _collect_args(self) -> list[str] | None:
        args: list[str] = []
        if self.current_form and self.current_form.has_subcommands:
            args.append(self.current_command.name)

        for dest, (field, widget) in self.field_widgets.items():
            if field.kind == "flag":
                if widget.get():
                    args.append(field.flag)
                continue
            value = widget.get().strip()
            if not value:
                if field.required:
                    messagebox.showwarning(
                        "Missing value", f"{field.label} is required.")
                    return None
                continue
            if field.flag:
                args.extend([field.flag, value])
            else:
                args.append(value)

        for dest, var in self.case_vars.items():
            value = var.get().strip()
            if value:
                args.extend([f"--{dest.replace('_', '-')}", value])

        return args

    def _on_run(self) -> None:
        if self.current_tool is None or self.run_handle is not None:
            return
        args = self._collect_args()
        if args is None:
            return

        self.last_output_path = None
        for dest in ("json", "csv"):
            field_widget = self.field_widgets.get(dest)
            if field_widget:
                value = field_widget[1].get().strip()
                if value:
                    self.last_output_path = Path(value)

        self._console_clear()
        self._console_write(f"$ {self.current_tool.name} "
                            f"{' '.join(args)}\n\n")
        self.output_nb.select(0)
        self.run_btn.pack_forget()
        self.cancel_btn.pack(side="right")
        self.status_var.set(f"Running {self.current_tool.name}…")

        self.run_handle = run(
            self.current_tool, args,
            on_line=lambda line: self.root.after(
                0, self._console_write, line + "\n"),
            on_done=lambda code: self.root.after(0, self._on_run_done,
                                                 code))

    def _on_cancel(self) -> None:
        if self.run_handle:
            self.run_handle.cancel()
            self.status_var.set("Cancelling…")

    def _on_run_done(self, code: int) -> None:
        self.run_handle = None
        self.cancel_btn.pack_forget()
        self.run_btn.pack(side="right")
        tag = "ok" if code == 0 else "err"
        self._console_write(f"\n[exit code {code}]\n", tag)
        self.status_var.set(
            f"{self.current_tool.name} finished (exit {code})")
        if code == 0 and self.last_output_path and \
                self.last_output_path.exists():
            self._load_results(self.last_output_path)

    def _on_open_native_gui(self) -> None:
        if self.current_tool is None:
            return
        args = self._collect_args() or []
        launch_native_gui(self.current_tool, args)
        self.status_var.set(f"Opened {self.current_tool.name}'s native "
                            f"GUI in a new window")

    # -- console / results ------------------------------------------
    def _console_clear(self) -> None:
        self.console_text.configure(state="normal")
        self.console_text.delete("1.0", "end")
        self.console_text.configure(state="disabled")

    def _console_write(self, text: str, tag: str | None = None) -> None:
        self.console_text.configure(state="normal")
        self.console_text.insert("end", text, tag or ())
        self.console_text.see("end")
        self.console_text.configure(state="disabled")

    def _load_results(self, path: Path) -> None:
        rows: list[dict] = []
        try:
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                rows = data if isinstance(data, list) else [data]
            elif path.suffix.lower() == ".csv":
                with path.open(encoding="utf-8-sig", newline="") as fh:
                    rows = list(csv.DictReader(fh))
        except (OSError, json.JSONDecodeError, csv.Error) as e:
            self._console_write(f"\n[could not load {path}: {e}]\n", "err")
            return

        self.results_tree.delete(*self.results_tree.get_children())
        if not rows:
            self.results_tree["columns"] = ()
            return
        columns = list(rows[0].keys())
        self.results_tree["columns"] = columns
        for c in columns:
            self.results_tree.heading(c, text=c)
            self.results_tree.column(c, width=140, stretch=True)
        for row in rows:
            self.results_tree.insert(
                "", "end", values=[row.get(c, "") for c in columns])
        self.output_nb.select(1)
