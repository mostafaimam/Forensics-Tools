from _synth import build_log, build_primary
from windows_reglog.logfile import BaseBlock, parse_log
from windows_reglog.replay import replay


def test_parse_log_entry_hashes_ok():
    log = build_log(seq=5, page_offset=0, page_data=b"NEW-PAGE-DATA")
    base, entries = parse_log(log)
    assert base.is_log
    assert len(entries) == 1
    e = entries[0]
    assert e.sequence == 5
    assert e.hash1_ok and e.hash2_ok
    assert len(e.pages) == 1 and e.pages[0].size == 4096


def test_replay_applies_and_marks_clean():
    primary = build_primary(seq1=5, seq2=4, marker=b"ORIGINAL-PAGE")
    log = build_log(seq=5, page_offset=0,
                    page_data=b"hbin" + b"\x00" * 16 + b"RECOVERED-CONTENT")

    res = replay(primary, [log], verify=True)
    assert res.applied_sequences == [5]
    assert res.pages_written == 1
    assert res.hash_failures == 0

    import struct
    seq1, seq2 = struct.unpack_from("<II", res.recovered, 4)
    assert seq1 == seq2 == 6
    # the hive-bin page now holds the log's content
    assert b"RECOVERED-CONTENT" in res.recovered[4096:8192]
    assert b"ORIGINAL-PAGE" not in res.recovered[4096:8192]


def test_clean_hive_is_untouched():
    primary = build_primary(seq1=7, seq2=7)
    log = build_log(seq=3, page_offset=0, page_data=b"stale")
    res = replay(primary, [log], verify=True)
    assert not res.changed
    assert res.recovered == primary


def test_reject_log_as_primary():
    import pytest

    from windows_reglog.logfile import RegLogError
    log = build_log(seq=1, page_offset=0, page_data=b"x")
    with pytest.raises(RegLogError):
        replay(log, [log])


def test_base_block_dirty_flag():
    assert BaseBlock.parse(build_primary(6, 5)).is_dirty
    assert not BaseBlock.parse(build_primary(6, 6)).is_dirty
