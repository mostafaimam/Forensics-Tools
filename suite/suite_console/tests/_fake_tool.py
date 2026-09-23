"""Build a minimal synthetic tool package matching the shape every
real tool in the repo has (cli.py with build_parser()/main()), for
fast, isolated introspect.py / runner.py tests."""

from __future__ import annotations

from pathlib import Path

from suite_console.discovery import ToolInfo

_SIMPLE_CLI = '''
import argparse
from pathlib import Path


def build_parser():
    p = argparse.ArgumentParser(prog="faketool")
    p.add_argument("target", help="a positional target")
    p.add_argument("--count", type=int, default=1, help="how many")
    p.add_argument("--verbose", action="store_true", help="be loud")
    p.add_argument("--mode", choices=["a", "b"], default="a")
    p.add_argument("--json", type=Path, help="write JSON here")
    # the provenance fields every real tool's cli.py adds via tracelib
    p.add_argument("--case-id", dest="case_id", default="")
    p.add_argument("--no-provenance", dest="no_provenance",
                   action="store_true")
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    print(f"target={a.target} count={a.count} verbose={a.verbose} "
         f"mode={a.mode} case_id={a.case_id!r}")
    if a.json:
        a.json.write_text('[{"x": 1, "y": "hi"}]', encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_SUB_CLI = '''
import argparse


def build_parser():
    p = argparse.ArgumentParser(prog="fakesub")
    sub = p.add_subparsers(dest="cmd")
    a = sub.add_parser("alpha")
    a.add_argument("thing")
    b = sub.add_parser("beta")
    b.add_argument("--power", type=int, default=1)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    print(f"cmd={a.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _write_tool(tmp_path: Path, name: str, cli_source: str) -> ToolInfo:
    root = tmp_path / name
    package_dir = root / name
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "cli.py").write_text(cli_source, encoding="utf-8")
    return ToolInfo(name=name, category="fake", description="a fake tool",
                    root=root, package_dir=package_dir, has_gui=False)


def make_simple_tool(tmp_path: Path) -> ToolInfo:
    return _write_tool(tmp_path, "faketool", _SIMPLE_CLI)


def make_subcommand_tool(tmp_path: Path) -> ToolInfo:
    return _write_tool(tmp_path, "fakesub", _SUB_CLI)
