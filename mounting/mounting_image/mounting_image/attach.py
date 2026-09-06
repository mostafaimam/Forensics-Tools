"""Platform attach helpers - build the commands to expose an image as a device.

Nothing here runs as root by itself; ``plan()`` returns the command list and
the CLI prints it (``--run`` executes it after a root check).  State is kept
in a small JSON registry so ``list`` / ``unmount`` can find prior sessions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

REGISTRY = Path(
    os.environ.get("MOUNTING_IMAGE_STATE",
                   Path.home() / ".local/share/mounting_image/mounts.json"))


@dataclass
class Session:
    image: str
    partition: int | None
    export_name: str
    host: str
    port: int
    nbd_device: str = ""
    mountpoint: str = ""
    server_pid: int = 0
    notes: list = field(default_factory=list)


def _load() -> list[dict]:
    try:
        return json.loads(REGISTRY.read_text())
    except (OSError, ValueError):
        return []


def _save(rows: list[dict]) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(rows, indent=2))


def register(sess: Session) -> None:
    rows = _load()
    rows.append(asdict(sess))
    _save(rows)


def sessions() -> list[dict]:
    return _load()


def deregister(port: int) -> dict | None:
    rows = _load()
    keep, gone = [], None
    for r in rows:
        if r.get("port") == port and gone is None:
            gone = r
        else:
            keep.append(r)
    _save(keep)
    return gone


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def plan_detach(nbd_device: str, mountpoint: str | None) -> list[list[str]]:
    """The equivalent shell commands (informational; --run does it in-process)."""
    cmds = []
    if mountpoint:
        cmds.append(["umount", mountpoint])
    if nbd_device:
        cmds.append(["#", "disconnect", nbd_device, "(mounting_image unmount",
                     "--run)"])
    return cmds


def run(cmds: list[list[str]]) -> tuple[bool, str]:
    out = []
    for cmd in cmds:
        exe = shutil.which(cmd[0])
        if exe is None:
            return False, f"command not found: {cmd[0]}"
        try:
            r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True)
        except OSError as e:
            return False, f"{cmd[0]}: {e}"
        out.append(f"$ {' '.join(cmd)}\n{r.stdout}{r.stderr}".rstrip())
        if r.returncode != 0:
            return False, "\n".join(out)
    return True, "\n".join(out)
