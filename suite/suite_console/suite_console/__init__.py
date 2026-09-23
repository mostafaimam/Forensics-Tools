r"""suite_console - a single luxurious desktop shell for every tool in
this repository.

Rather than hand-wire an integration per tool, this exploits the one
thing all 142 of them already share: a `cli.py` exposing
`build_parser()` (a standard `argparse.ArgumentParser`, including the
`tracelib` provenance flags every tool adds the same way) and `main()`.
`discovery.py` walks the repo for `pyproject.toml` files to build a
catalogue; `introspect.py` turns each tool's *own* argparse spec into
a form, including its subcommands where it has them (e.g.
`mounting_fvde info/unlock/decrypt`); `runner.py` drives the tool as a
subprocess (`python -m <package>.cli ...`) so one tool's crash or
`sys.exit()` can never take the console down with it, and streams its
stdout/stderr live. A tool that already ships its own bespoke GUI
(`gui.py` / `run_gui()`) can still be opened directly, as its own
window, alongside the generic form.

Adding tool #143 later needs no change here at all - it is discovered
automatically the moment its directory appears with a `pyproject.toml`
and a `cli.py` matching the same shape every other tool already uses.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
