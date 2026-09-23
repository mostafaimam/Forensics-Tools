from __future__ import annotations

import json
import threading
import time

import pytest

import _fake_tool

from suite_console.runner import build_command, run


def test_build_command_shape(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    cmd = build_command(tool, ["hello", "--count", "3"])
    assert cmd[1:3] == ["-m", "faketool.cli"]
    assert cmd[-2:] == ["hello", "3"] or "--count" in cmd


def test_run_streams_output_and_completes(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    lines: list[str] = []
    done = threading.Event()
    codes = []

    def on_line(line):
        lines.append(line)

    def on_done(code):
        codes.append(code)
        done.set()

    run(tool, ["hello-target", "--count", "2", "--verbose"],
       on_line=on_line, on_done=on_done)
    assert done.wait(timeout=20)
    assert codes == [0]
    joined = "\n".join(lines)
    assert "target=hello-target" in joined
    assert "count=2" in joined
    assert "verbose=True" in joined


def test_run_writes_json_output_file(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    out = tmp_path / "result.json"
    done = threading.Event()

    def on_done(code):
        done.set()

    run(tool, ["x", "--json", str(out)], on_line=lambda _l: None,
       on_done=on_done)
    assert done.wait(timeout=20)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data == [{"x": 1, "y": "hi"}]


def test_run_nonzero_exit_reported(tmp_path):
    tool = _fake_tool.make_simple_tool(tmp_path)
    codes = []
    done = threading.Event()

    def on_done(code):
        codes.append(code)
        done.set()

    # an unsatisfiable choice makes argparse itself exit non-zero
    run(tool, ["x", "--mode", "not-a-real-choice"], on_line=lambda _l: None,
       on_done=on_done)
    assert done.wait(timeout=20)
    assert codes[0] != 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
