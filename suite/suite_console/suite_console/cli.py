from __future__ import annotations

import argparse
import sys

from suite_console import __version__
from suite_console.discovery import discover_tools, find_repo_root


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="suite_console",
        description="A single desktop shell for every tool in this "
                    "repository. Auto-discovers every category/name "
                    "package with a pyproject.toml and a cli.py, "
                    "introspects that tool's own argparse spec to build "
                    "a form, and runs it as an isolated subprocess. "
                    "With no flags, opens the GUI directly.")
    p.add_argument("--version", action="version",
                   version=f"suite_console {__version__}")
    p.add_argument("--list", action="store_true",
                   help="print every discovered tool, one per line, "
                   "and exit (no GUI)")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)

    if a.list:
        tools = discover_tools()
        for t in sorted(tools, key=lambda x: (x.category, x.name)):
            print(f"{t.category:<12} {t.name:<28} {t.description}")
        print(f"\n{len(tools)} tool(s) found under {find_repo_root()}",
             file=sys.stderr)
        return 0

    from suite_console.app import ConsoleApp
    import tkinter as tk

    root = tk.Tk()
    ConsoleApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
