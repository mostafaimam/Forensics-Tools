"""Tie it together: open an ``automaticDestinations-ms`` jump list, parse the
``DestList`` MRU stream, and pair each entry with its LNK stream."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_jumplist.appids import lookup as appid_lookup
from windows_jumplist.destlist import DestListEntry
from windows_jumplist.destlist import parse as parse_destlist
from windows_jumplist.lnk import Lnk
from windows_jumplist.lnk import parse as parse_lnk
from windows_jumplist.ole import OleError, OleFile

_APPID_RE = re.compile(r"^([0-9a-fA-F]{5,20})\.(automatic|custom)Destinations-ms$")


@dataclass
class JumpListItem:
    entry_number: int
    mru_position: int
    dest_path: str
    last_used: object
    hostname: str
    pinned: bool
    interaction_count: int
    lnk: Lnk | None = None

    @property
    def target_path(self) -> str:
        if self.lnk and self.lnk.target_path:
            return self.lnk.target_path
        return self.dest_path


@dataclass
class JumpList:
    source: str
    app_id: str = ""
    application: str = ""
    kind: str = "automatic"
    destlist_version: int = 0
    entry_count: int = 0
    pinned_count: int = 0
    items: list = field(default_factory=list)
    orphan_streams: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def _app_id(name: str) -> str:
    m = _APPID_RE.match(name)
    return m.group(1).lower() if m else ""


def parse_automatic(data: bytes, source: str = "<bytes>") -> JumpList:
    jl = JumpList(source=source)
    name = Path(source).name
    jl.app_id = _app_id(name)
    jl.application = appid_lookup(jl.app_id)

    try:
        ole = OleFile(data)
    except OleError as e:
        raise OleError(f"{source}: {e}")

    streams = {s for s in ole.list_streams()}
    lnk_by_entry: dict[int, Lnk] = {}
    for s in streams:
        if s == "DestList":
            continue
        try:
            num = int(s, 16)
        except ValueError:
            try:
                num = int(s)
            except ValueError:
                continue
        try:
            lnk_by_entry[num] = parse_lnk(ole.open_stream(s), f"{source}::{s}")
        except Exception as e:  # noqa: BLE001
            jl.warnings.append(f"stream {s}: {e}")

    dl = None
    if "DestList" in streams:
        try:
            dl = parse_destlist(ole.open_stream("DestList"))
        except (ValueError, OleError) as e:
            jl.warnings.append(f"DestList: {e}")
    else:
        jl.warnings.append("no DestList stream")

    if dl is None:
        for num, lnk in sorted(lnk_by_entry.items()):
            jl.items.append(JumpListItem(num, -1, lnk.target_path, None, "",
                                         False, 0, lnk))
        return jl

    jl.destlist_version = dl.version
    jl.entry_count = dl.entry_count
    jl.pinned_count = dl.pinned_count

    used = set()
    for e in dl.entries:
        lnk = lnk_by_entry.get(e.entry_number)
        used.add(e.entry_number)
        jl.items.append(JumpListItem(
            entry_number=e.entry_number, mru_position=e.mru_position,
            dest_path=e.path, last_used=e.last_used, hostname=e.hostname,
            pinned=e.pinned, interaction_count=e.interaction_count, lnk=lnk,
        ))
    jl.orphan_streams = sorted(str(k) for k in lnk_by_entry if k not in used)
    return jl


def parse_file(path) -> JumpList:
    return parse_automatic(Path(path).read_bytes(), str(path))
