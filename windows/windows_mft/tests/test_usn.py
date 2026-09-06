from _synth import build_usn_journal
from windows_mft.ntfs.usn import iter_usn


def test_parses_all_records_across_sparse_gap():
    blob, recs = build_usn_journal()
    got = list(iter_usn(blob))
    assert len(got) == 4
    assert [r.usn for r in got] == [0x100, 0x180, 0x200, 0x280]


def test_reason_and_name_decoding():
    blob, _ = build_usn_journal()
    got = list(iter_usn(blob))
    create = got[0]
    assert create.name == "notes.txt"
    assert create.file_entry == 40
    assert create.parent_entry == 5
    assert "FILE_CREATE" in create.reason_names()

    deleted = got[3]
    assert deleted.name == "evil.exe"
    assert set(deleted.reason_names()) == {"FILE_DELETE", "CLOSE"}
    assert deleted.timestamp is not None and deleted.timestamp.year == 2024


def test_empty_input():
    assert list(iter_usn(b"")) == []
    assert list(iter_usn(b"\x00" * 4096)) == []
