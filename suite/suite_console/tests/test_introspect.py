from __future__ import annotations

import pytest

import _fake_tool

from suite_console.introspect import build_form


def test_build_form_simple_tool(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    form = build_form(tool)
    assert not form.has_subcommands
    assert len(form.commands) == 1
    fields = {f.dest: f for f in form.commands[0].fields}
    assert "target" in fields
    assert fields["target"].kind == "text"
    assert fields["target"].required
    assert "count" in fields
    assert fields["count"].kind == "int"
    assert "verbose" in fields
    assert fields["verbose"].kind == "flag"
    assert "mode" in fields
    assert fields["mode"].kind == "choice"
    assert fields["mode"].choices == ["a", "b"]
    assert "json" in fields
    assert fields["json"].kind == "outpath"


def test_build_form_filters_provenance_fields(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    form = build_form(tool)
    dests = {f.dest for f in form.commands[0].fields}
    assert "case_id" not in dests
    assert "no_provenance" not in dests


def test_build_form_subcommand_tool(tmp_path):
    tool = _fake_tool.make_subcommand_tool(tmp_path)
    form = build_form(tool)
    assert form.has_subcommands
    names = {c.name for c in form.commands}
    assert names == {"alpha", "beta"}
    alpha = next(c for c in form.commands if c.name == "alpha")
    beta = next(c for c in form.commands if c.name == "beta")
    assert {f.dest for f in alpha.fields} == {"thing"}
    assert {f.dest for f in beta.fields} == {"power"}
    assert next(f for f in beta.fields if f.dest == "power").kind == "int"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
