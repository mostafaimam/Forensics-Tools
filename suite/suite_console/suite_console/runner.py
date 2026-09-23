"""Run a tool as an isolated subprocess and stream its output.

Subprocess isolation, not an in-process call, on purpose: one tool's
`sys.exit()` or an unexpected crash can never take the console itself
down, and each run gets a clean interpreter state.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Callable

from suite_console.discovery import ToolInfo

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


@dataclass
class RunHandle:
    process: subprocess.Popen
    thread: threading.Thread

    def cancel(self) -> None:
        try:
            self.process.terminate()
        except OSError:
            pass


def build_command(tool: ToolInfo, args: list[str]) -> list[str]:
    return [sys.executable, "-m", f"{tool.name}.cli", *args]


def _env_for(tool: ToolInfo) -> dict:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    root_str = str(tool.root)
    env["PYTHONPATH"] = os.pathsep.join(
        [root_str, existing] if existing else [root_str])
    return env


def run(tool: ToolInfo, args: list[str], *,
       on_line: Callable[[str], None],
       on_done: Callable[[int], None]) -> RunHandle:
    cmd = build_command(tool, args)
    proc = subprocess.Popen(
        cmd, cwd=str(tool.root), env=_env_for(tool),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, creationflags=_CREATE_NO_WINDOW,
    )

    def _pump():
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                on_line(line.rstrip("\n"))
        finally:
            code = proc.wait()
            on_done(code)

    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    return RunHandle(process=proc, thread=t)


def launch_native_gui(tool: ToolInfo,
                      extra_args: list[str] | None = None) -> \
        subprocess.Popen:
    args = [*(extra_args or []), "--gui"]
    cmd = build_command(tool, args)
    return subprocess.Popen(cmd, cwd=str(tool.root), env=_env_for(tool),
                            creationflags=_CREATE_NO_WINDOW)
