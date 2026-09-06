from datetime import datetime, timezone

import pytest

from _synth import build_jumplist, build_ole, destlist_v4
from windows_jumplist.destlist import parse as parse_destlist
from windows_jumplist.jumplist import parse_automatic
from windows_jumplist.ole import OleError, OleFile


def test_ole_roundtrip():
    ole = OleFile(build_ole({"DestList": b"x" * 5000, "1": b"y" * 4200}))
    assert set(ole.list_streams()) == {"DestList", "1"}
    assert ole.open_stream("DestList") == b"x" * 5000
    assert ole.open_stream("1") == b"y" * 4200
    with pytest.raises(OleError):
        ole.open_stream("nope")


def test_ole_rejects_non_ole():
    with pytest.raises(OleError):
        OleFile(b"not an ole file" + b"\x00" * 600)


def test_destlist_parse():
    when = datetime(2024, 6, 1, 9, 0, tzinfo=timezone.utc)
    blob = destlist_v4([
        (5, r"C:\a\b.txt", when, False),
        (2, r"D:\x\y.doc", when, True),
    ])
    dl = parse_destlist(blob)
    assert dl.version == 4 and dl.entry_count == 2
    assert len(dl.entries) == 2
    assert dl.entries[0].entry_number == 5
    assert dl.entries[0].path == r"C:\a\b.txt"
    assert dl.entries[0].last_used == when
    assert dl.entries[0].hostname == "WORKSTATION"
    assert dl.entries[1].pinned is True


def test_full_jumplist():
    data, name = build_jumplist(app_id="12dc1ea8e34b5a6")
    jl = parse_automatic(data, name)
    assert jl.app_id == "12dc1ea8e34b5a6"
    assert "Photo" in jl.application
    assert jl.destlist_version == 4
    assert len(jl.items) == 2

    first = jl.items[0]
    assert first.entry_number == 3
    assert first.mru_position == 0
    assert first.target_path == r"C:\Users\a\Desktop\latest.png"
    assert first.lnk is not None
    assert first.lnk.drive_serial == "AABBCCDD"
    assert first.hostname == "WORKSTATION"
    assert jl.items[1].pinned is True


def test_jumplist_without_destlist():
    data = build_ole({"1": _mini_lnk()})
    jl = parse_automatic(data, "abc.automaticDestinations-ms")
    assert jl.warnings
    assert len(jl.items) == 1
    assert jl.items[0].lnk is not None


def _mini_lnk() -> bytes:
    from _lnk_synth import build_lnk
    return build_lnk(target=r"C:\x\y.txt")
