"""Turn a tool's own argparse spec into a declarative form.

Every tool's `build_parser()` already carries everything a form needs:
flag names, help text, choices, required-ness, and (via
`tracelib.add_arguments`) a common set of case-metadata fields shared
across all 142 tools - filtered out here since the console renders
those once, globally, rather than 142 times.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import dataclass, field

from suite_console.discovery import ToolInfo

_PROVENANCE_DESTS = {
    "case_id", "examiner", "evidence_id", "notes", "no_provenance",
    "no_hash_inputs", "max_input_bytes", "max_records", "wall_seconds",
}
_SKIP_DESTS = {"help", "version", "gui"}
_OUTPUT_DESTS = {"csv", "json", "out", "output", "dump_dir", "extract_dir"}
_DIR_HINTS = ("_dir", "dir_")


class IntrospectError(RuntimeError):
    pass


@dataclass
class FieldSpec:
    dest: str
    flag: str | None           # None for a positional argument
    label: str
    kind: str                  # text | int | path | outpath | dir | flag | choice
    required: bool
    default: object
    help: str
    choices: list[str] | None = None


@dataclass
class CommandSpec:
    name: str                  # "" when the tool has no subcommands
    fields: list[FieldSpec] = field(default_factory=list)


@dataclass
class FormSpec:
    commands: list[CommandSpec]
    has_subcommands: bool


def _looks_like_path_type(action) -> bool:
    t = getattr(action, "type", None)
    return t is not None and "Path" in str(t)


def _field_from_action(action) -> FieldSpec | None:
    if action.dest in _SKIP_DESTS or action.dest in _PROVENANCE_DESTS:
        return None
    if isinstance(action, argparse._HelpAction):
        return None

    is_positional = not action.option_strings
    flag = action.option_strings[-1] if action.option_strings else None

    if isinstance(action, (argparse._StoreTrueAction,
                           argparse._StoreFalseAction)):
        kind = "flag"
    elif action.choices:
        kind = "choice"
    elif action.type is int:
        kind = "int"
    elif _looks_like_path_type(action):
        if action.dest in _OUTPUT_DESTS or any(
                h in action.dest for h in _DIR_HINTS):
            kind = "dir" if any(h in action.dest for h in _DIR_HINTS) \
                else "outpath"
        else:
            kind = "path"
    else:
        kind = "text"

    label = (flag or action.dest).lstrip("-").replace("-", " ")
    required = bool(getattr(action, "required", False)) or (
        is_positional and action.nargs not in ("?", "*"))
    return FieldSpec(dest=action.dest, flag=flag, label=label, kind=kind,
                     required=required, default=action.default,
                     help=action.help or "",
                     choices=list(action.choices) if action.choices
                     else None)


def _import_cli(tool: ToolInfo):
    root_str = str(tool.root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    module_name = f"{tool.name}.cli"
    if module_name in sys.modules:
        return sys.modules[module_name]
    try:
        return importlib.import_module(module_name)
    except Exception as e:  # noqa: BLE001
        raise IntrospectError(f"{tool.name}: could not import its CLI "
                              f"module ({e})") from e


def build_form(tool: ToolInfo) -> FormSpec:
    mod = _import_cli(tool)
    try:
        parser = mod.build_parser()
    except Exception as e:  # noqa: BLE001
        raise IntrospectError(f"{tool.name}: build_parser() failed "
                              f"({e})") from e

    sub_action = None
    top_fields: list[FieldSpec] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            sub_action = action
            continue
        f = _field_from_action(action)
        if f:
            top_fields.append(f)

    if sub_action is None:
        return FormSpec(commands=[CommandSpec(name="", fields=top_fields)],
                        has_subcommands=False)

    commands = []
    for sub_name, sub_parser in sub_action.choices.items():
        fields = []
        for action in sub_parser._actions:
            f = _field_from_action(action)
            if f:
                fields.append(f)
        commands.append(CommandSpec(name=sub_name, fields=fields))
    return FormSpec(commands=commands, has_subcommands=True)
